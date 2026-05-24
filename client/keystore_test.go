package client

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/brendanbenshoof/sneakernet/blockstore"
)

func TestKeystoreRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")
	password := []byte("hunter2")

	ks, err := NewKeystore(password)
	if err != nil {
		t.Fatalf("NewKeystore: %v", err)
	}
	id, err := ks.Add("alice")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	wantPub := id.Key.PublicKey().Bytes()

	if err := ks.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	ks2, err := LoadKeystore(path, password)
	if err != nil {
		t.Fatalf("LoadKeystore: %v", err)
	}
	ids := ks2.List()
	if len(ids) != 1 || ids[0].Name != "alice" {
		t.Fatalf("expected [alice], got %v", ids)
	}
	if string(ids[0].Key.PublicKey().Bytes()) != string(wantPub) {
		t.Fatal("public key mismatch after reload")
	}
}

func TestKeystoreWrongPassword(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")

	ks, err := NewKeystore([]byte("correct"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Add("bob"); err != nil {
		t.Fatal(err)
	}
	if err := ks.Save(path); err != nil {
		t.Fatal(err)
	}

	_, err = LoadKeystore(path, []byte("wrong"))
	if err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
}

func TestKeystoreAddRemove(t *testing.T) {
	ks, err := NewKeystore([]byte("pass"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ks.Add("alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Add("bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Add("alice"); err == nil {
		t.Fatal("expected error adding duplicate name")
	}

	if !ks.Remove("alice") {
		t.Fatal("Remove returned false for existing identity")
	}
	if ks.Remove("alice") {
		t.Fatal("Remove returned true for already-removed identity")
	}

	ids := ks.List()
	if len(ids) != 1 || ids[0].Name != "bob" {
		t.Fatalf("expected [bob], got %v", ids)
	}
}

func TestKeystoreChangePassword(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")

	ks, err := NewKeystore([]byte("old"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := ks.Add("carol")
	if err != nil {
		t.Fatal(err)
	}
	wantPub := id.Key.PublicKey().Bytes()

	if err := ks.ChangePassword([]byte("new")); err != nil {
		t.Fatal(err)
	}
	if err := ks.Save(path); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadKeystore(path, []byte("old")); err == nil {
		t.Fatal("old password should no longer work")
	}

	ks2, err := LoadKeystore(path, []byte("new"))
	if err != nil {
		t.Fatalf("LoadKeystore with new password: %v", err)
	}
	ids := ks2.List()
	if len(ids) != 1 || ids[0].Name != "carol" {
		t.Fatalf("unexpected identities after password change: %v", ids)
	}
	if string(ids[0].Key.PublicKey().Bytes()) != string(wantPub) {
		t.Fatal("key changed after password rotation")
	}
}

func TestKeystoreAtomicSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")

	ks, err := NewKeystore([]byte("pass"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.Save(path); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file left behind after Save")
	}
}

func TestKeystoreMultiKeyClient(t *testing.T) {
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

	ks, err := NewKeystore([]byte("pass"))
	if err != nil {
		t.Fatal(err)
	}
	id1, _ := ks.Add("alice")
	id2, _ := ks.Add("bob")

	for _, id := range []*Identity{id1, id2} {
		mp := MessagePayload{MsgType: MsgTypeText, FragTotal: 1, Content: []byte("hi " + id.Name)}
		payload, err := Encrypt(id.Key.PublicKey(), mp)
		if err != nil {
			t.Fatal(err)
		}
		var stamp blockstore.Stamp
		if _, err := bs.Put(stamp, payload); err != nil {
			t.Fatal(err)
		}
	}

	c := New(bs, ms, ks.Keys(), nil)
	found, err := c.Scrape(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if found != 2 {
		t.Fatalf("expected 2 messages, got %d", found)
	}
}
