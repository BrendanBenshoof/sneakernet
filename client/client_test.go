package client

import (
	"context"
	"testing"
	"time"

	"github.com/brendanbenshoof/sneakernet/blockstore"
)

func TestScrape(t *testing.T) {
	bs, err := blockstore.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	defer bs.Close()

	ms, err := OpenMessageStore(":memory:")
	if err != nil {
		t.Fatalf("open message store: %v", err)
	}
	defer ms.Close()

	recipientKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"hello sneakernet", "second message"}

	// Two messages for recipient.
	for _, text := range want {
		mp := MessagePayload{MsgType: MsgTypeText, FragTotal: 1, Content: []byte(text)}
		payload, err := Encrypt(recipientKey.PublicKey(), mp)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		var stamp blockstore.Stamp
		if _, err := bs.Put(stamp, payload); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}

	// One message for someone else — should not appear.
	noise, err := Encrypt(otherKey.PublicKey(), MessagePayload{MsgType: MsgTypeText, FragTotal: 1, Content: []byte("not for you")})
	if err != nil {
		t.Fatal(err)
	}
	var stamp blockstore.Stamp
	if _, err := bs.Put(stamp, noise); err != nil {
		t.Fatal(err)
	}

	c := New(bs, ms, []*Identity{{Name: "test", Key: recipientKey}}, nil)
	found, err := c.Scrape(context.Background())
	if err != nil {
		t.Fatalf("Scrape: %v", err)
	}
	if found != len(want) {
		t.Fatalf("Scrape found %d messages, want %d", found, len(want))
	}

	msgs, err := ms.ListMessages()
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != len(want) {
		t.Fatalf("ListMessages returned %d, want %d", len(msgs), len(want))
	}
	got := map[string]bool{}
	for _, m := range msgs {
		got[string(m.Content)] = true
	}
	for _, text := range want {
		if !got[text] {
			t.Errorf("message %q not found in store", text)
		}
	}

	// Second scrape with no new blocks — checkpoint should prevent re-processing.
	found2, err := c.Scrape(context.Background())
	if err != nil {
		t.Fatalf("second Scrape: %v", err)
	}
	if found2 != 0 {
		t.Fatalf("second Scrape found %d, want 0 (checkpoint not working)", found2)
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		content []byte
	}{
		{"empty", []byte{}},
		{"short", []byte("hi")},
		{"max", make([]byte, V2MaxContent)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mp := MessagePayload{MsgType: MsgTypeText, FragTotal: 1, Content: tc.content}
			payload, err := Encrypt(key.PublicKey(), mp)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			got, err := tryDecrypt(key, payload)
			if err != nil {
				t.Fatalf("tryDecrypt: %v", err)
			}
			if string(got.Content) != string(tc.content) {
				t.Fatalf("content mismatch: got %q want %q", got.Content, tc.content)
			}
		})
	}
}

func TestTryDecryptWrongKey(t *testing.T) {
	recipient, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	other, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	mp := MessagePayload{MsgType: MsgTypeText, FragTotal: 1, Content: []byte("secret")}
	payload, err := Encrypt(recipient.PublicKey(), mp)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tryDecrypt(other, payload)
	if err != ErrNotOurMessage {
		t.Fatalf("expected ErrNotOurMessage, got %v", err)
	}
}

func TestCheckpointAdvances(t *testing.T) {
	bs, err := blockstore.OpenSQLite(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer bs.Close()

	ms, err := OpenMessageStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer ms.Close()

	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	c := New(bs, ms, []*Identity{{Name: "test", Key: key}}, nil)

	putBlock := func(text string) {
		t.Helper()
		mp := MessagePayload{MsgType: MsgTypeText, FragTotal: 1, Content: []byte(text)}
		payload, err := Encrypt(key.PublicKey(), mp)
		if err != nil {
			t.Fatal(err)
		}
		var stamp blockstore.Stamp
		if _, err := bs.Put(stamp, payload); err != nil {
			t.Fatal(err)
		}
	}

	putBlock("before first scrape")
	if n, err := c.Scrape(context.Background()); err != nil || n != 1 {
		t.Fatalf("first scrape: got (%d, %v), want (1, nil)", n, err)
	}

	// Sleep just past the checkpoint resolution (1 s unix).
	time.Sleep(1100 * time.Millisecond)

	putBlock("after first scrape")
	if n, err := c.Scrape(context.Background()); err != nil || n != 1 {
		t.Fatalf("second scrape: got (%d, %v), want (1, nil)", n, err)
	}
}

func TestFragmentReassembly(t *testing.T) {
	bs, err := blockstore.OpenSQLite(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer bs.Close()

	ms, err := OpenMessageStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer ms.Close()

	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	// Build a message that requires exactly 2 fragments.
	fullContent := make([]byte, V2MaxContent+100)
	for i := range fullContent {
		fullContent[i] = byte(i % 251)
	}

	var fragID [32]byte
	fragID[0] = 0xAB

	chunks := [][]byte{fullContent[:V2MaxContent], fullContent[V2MaxContent:]}
	var stamp blockstore.Stamp
	for i, chunk := range chunks {
		mp := MessagePayload{
			MsgType:   MsgTypeText,
			FragID:    fragID,
			FragIndex: uint16(i),
			FragTotal: 2,
			Content:   chunk,
		}
		payload, err := Encrypt(key.PublicKey(), mp)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := bs.Put(stamp, payload); err != nil {
			t.Fatal(err)
		}
	}

	c := New(bs, ms, []*Identity{{Name: "test", Key: key}}, nil)
	found, err := c.Scrape(context.Background())
	if err != nil {
		t.Fatalf("Scrape: %v", err)
	}
	if found != 1 {
		t.Fatalf("Scrape found %d, want 1 assembled message", found)
	}

	msgs, err := ms.ListMessages()
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if string(msgs[0].Content) != string(fullContent) {
		t.Fatal("reassembled content does not match original")
	}
}

func TestSignedRoundtrip(t *testing.T) {
	recipientKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	ks, err := NewKeystore([]byte("pass"))
	if err != nil {
		t.Fatal(err)
	}
	senderID, err := ks.Add("alice")
	if err != nil {
		t.Fatal(err)
	}

	// ed25519.PrivateKey is 64 bytes: first 32 = seed, last 32 = public key.
	var senderPub [32]byte
	copy(senderPub[:], senderID.SignKey[32:])

	mp := MessagePayload{
		MsgType:   MsgTypeText,
		FragTotal: 1,
		Content:   []byte("signed hello"),
		SenderPub: senderPub,
	}
	payload, err := EncryptSigned(recipientKey.PublicKey(), mp, senderID.SignKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tryDecrypt(recipientKey, payload)
	if err != nil {
		t.Fatalf("tryDecrypt: %v", err)
	}
	if string(got.Content) != "signed hello" {
		t.Fatalf("content mismatch: %q", got.Content)
	}
	if got.SenderPub != senderPub {
		t.Fatal("sender pub mismatch")
	}
}
