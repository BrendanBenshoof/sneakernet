package client

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	kdfSaltSize     = 32
	kdfTime    uint32 = 2
	kdfMemory  uint32 = 64 * 1024 // 64 MB
	kdfThreads uint8  = 4
	kdfKeyLen  uint32 = 32

	keystoreVersion = 1
)

// Identity is a named X25519 key pair held in a Keystore.
type Identity struct {
	Name string
	Key  *ecdh.PrivateKey
}

// Keystore is a password-protected collection of named X25519 identities.
// Load it once at startup; all keys are decrypted into memory.
type Keystore struct {
	masterKey  [kdfKeyLen]byte
	salt       []byte
	kdfTime    uint32
	kdfMemory  uint32
	kdfThreads uint8
	identities []*Identity
}

// NewKeystore creates an empty Keystore protected by password.
func NewKeystore(password []byte) (*Keystore, error) {
	salt := make([]byte, kdfSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	k := &Keystore{
		salt:       salt,
		kdfTime:    kdfTime,
		kdfMemory:  kdfMemory,
		kdfThreads: kdfThreads,
	}
	k.masterKey = deriveKey(password, salt, kdfTime, kdfMemory, kdfThreads)
	return k, nil
}

// LoadKeystore reads and decrypts a keystore file at path using password.
// Returns an error immediately if the password is wrong or the file is corrupted.
func LoadKeystore(path string, password []byte) (*Keystore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("client: load keystore: %w", err)
	}

	var f keystoreFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("client: load keystore: %w", err)
	}
	if f.Version != keystoreVersion {
		return nil, fmt.Errorf("client: unsupported keystore version %d", f.Version)
	}

	masterKey := deriveKey(password, f.Salt, f.KDFTime, f.KDFMemory, f.KDFThreads)

	k := &Keystore{
		masterKey:  masterKey,
		salt:       f.Salt,
		kdfTime:    f.KDFTime,
		kdfMemory:  f.KDFMemory,
		kdfThreads: f.KDFThreads,
	}

	for _, rec := range f.Identities {
		privBytes, err := ksDecrypt(masterKey, rec.Nonce, rec.Ciphertext)
		if err != nil {
			return nil, fmt.Errorf("client: load keystore: wrong password or corrupted data")
		}
		privKey, err := ecdh.X25519().NewPrivateKey(privBytes)
		if err != nil {
			return nil, fmt.Errorf("client: load keystore: invalid key %q: %w", rec.Name, err)
		}
		k.identities = append(k.identities, &Identity{Name: rec.Name, Key: privKey})
	}

	return k, nil
}

// Save encrypts all identities and writes the keystore to path.
// The file is written atomically via a temp file so a crash mid-write
// never leaves a truncated keystore.
func (k *Keystore) Save(path string) error {
	f := keystoreFile{
		Version:    keystoreVersion,
		Salt:       k.salt,
		KDFTime:    k.kdfTime,
		KDFMemory:  k.kdfMemory,
		KDFThreads: k.kdfThreads,
	}

	for _, id := range k.identities {
		nonce, ct, err := ksEncrypt(k.masterKey, id.Key.Bytes())
		if err != nil {
			return fmt.Errorf("client: save keystore: encrypt %q: %w", id.Name, err)
		}
		f.Identities = append(f.Identities, identityRecord{
			Name:       id.Name,
			Nonce:      nonce,
			Ciphertext: ct,
		})
	}

	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("client: save keystore: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("client: save keystore: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("client: save keystore: %w", err)
	}
	return nil
}

// Add generates a fresh X25519 identity under name and returns it.
// Returns an error if name is already taken.
func (k *Keystore) Add(name string) (*Identity, error) {
	if k.get(name) != nil {
		return nil, fmt.Errorf("client: identity %q already exists", name)
	}
	privKey, err := GenerateKey()
	if err != nil {
		return nil, err
	}
	id := &Identity{Name: name, Key: privKey}
	k.identities = append(k.identities, id)
	return id, nil
}

// Import stores an existing private key under name.
// Returns an error if name is already taken.
func (k *Keystore) Import(name string, privKey *ecdh.PrivateKey) error {
	if k.get(name) != nil {
		return fmt.Errorf("client: identity %q already exists", name)
	}
	k.identities = append(k.identities, &Identity{Name: name, Key: privKey})
	return nil
}

// Remove deletes the identity with the given name.
// Returns false if no such identity exists.
func (k *Keystore) Remove(name string) bool {
	for i, id := range k.identities {
		if id.Name == name {
			k.identities = append(k.identities[:i], k.identities[i+1:]...)
			return true
		}
	}
	return false
}

// List returns all identities in the keystore.
func (k *Keystore) List() []*Identity {
	out := make([]*Identity, len(k.identities))
	copy(out, k.identities)
	return out
}

// Keys returns the private key for every stored identity, suitable for
// passing to client.New for multi-identity scraping.
func (k *Keystore) Keys() []*ecdh.PrivateKey {
	keys := make([]*ecdh.PrivateKey, len(k.identities))
	for i, id := range k.identities {
		keys[i] = id.Key
	}
	return keys
}

// ChangePassword re-keys the master key with newPassword and a fresh salt.
// Call Save afterwards to persist the change.
func (k *Keystore) ChangePassword(newPassword []byte) error {
	salt := make([]byte, kdfSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	k.salt = salt
	k.masterKey = deriveKey(newPassword, salt, k.kdfTime, k.kdfMemory, k.kdfThreads)
	return nil
}

func (k *Keystore) get(name string) *Identity {
	for _, id := range k.identities {
		if id.Name == name {
			return id
		}
	}
	return nil
}

// --- on-disk format ---

type keystoreFile struct {
	Version    int              `json:"version"`
	Salt       []byte           `json:"salt"`
	KDFTime    uint32           `json:"kdf_time"`
	KDFMemory  uint32           `json:"kdf_memory"`
	KDFThreads uint8            `json:"kdf_threads"`
	Identities []identityRecord `json:"identities"`
}

type identityRecord struct {
	Name       string `json:"name"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// --- crypto helpers ---

func deriveKey(password, salt []byte, time, memory uint32, threads uint8) [kdfKeyLen]byte {
	raw := argon2.IDKey(password, salt, time, memory, threads, kdfKeyLen)
	return [kdfKeyLen]byte(raw)
}

func ksEncrypt(masterKey [kdfKeyLen]byte, plaintext []byte) (nonce, ciphertext []byte, err error) {
	aead, err := chacha20poly1305.NewX(masterKey[:])
	if err != nil {
		return nil, nil, err
	}
	n := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(n); err != nil {
		return nil, nil, err
	}
	return n, aead.Seal(nil, n, plaintext, nil), nil
}

func ksDecrypt(masterKey [kdfKeyLen]byte, nonce, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(masterKey[:])
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed")
	}
	return plain, nil
}
