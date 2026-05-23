package client

import (
	"context"
	"crypto/ecdh"
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
		payload, err := Encrypt(recipientKey.PublicKey(), []byte(text))
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		var stamp blockstore.Stamp
		if _, err := bs.Put(stamp, payload); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}

	// One message for someone else — should not appear.
	noise, err := Encrypt(otherKey.PublicKey(), []byte("not for you"))
	if err != nil {
		t.Fatal(err)
	}
	var stamp blockstore.Stamp
	if _, err := bs.Put(stamp, noise); err != nil {
		t.Fatal(err)
	}

	c := New(bs, ms, []*ecdh.PrivateKey{recipientKey}, nil)
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
		name string
		msg  []byte
	}{
		{"empty", []byte{}},
		{"short", []byte("hi")},
		{"max", make([]byte, maxMessageSize)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := Encrypt(key.PublicKey(), tc.msg)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			got, err := tryDecrypt(key, payload)
			if err != nil {
				t.Fatalf("tryDecrypt: %v", err)
			}
			if string(got) != string(tc.msg) {
				t.Fatalf("content mismatch: got %q want %q", got, tc.msg)
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
	payload, err := Encrypt(recipient.PublicKey(), []byte("secret"))
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

	c := New(bs, ms, []*ecdh.PrivateKey{key}, nil)

	putBlock := func(text string) {
		t.Helper()
		payload, err := Encrypt(key.PublicKey(), []byte(text))
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
