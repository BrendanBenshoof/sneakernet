package client

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
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

// Identity is a named key pair held in a Keystore.
// Key is the X25519 encryption key; SignKey is the Ed25519 signing key.
type Identity struct {
	Name    string
	Key     *ecdh.PrivateKey
	SignKey ed25519.PrivateKey
}

// Channel is a named symmetric channel key. Anyone who knows the passphrase
// (from which Key is derived) can decrypt and post to the channel anonymously.
type Channel struct {
	Name string
	Key  [32]byte
}

// Keystore is a password-protected collection of named identities and channel keys.
// Load it once at startup; all keys are decrypted into memory.
type Keystore struct {
	masterKey  [kdfKeyLen]byte
	salt       []byte
	kdfTime    uint32
	kdfMemory  uint32
	kdfThreads uint8
	identities []*Identity
	channels   []*Channel
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
// If any identity is missing a signing key (old keystore), a fresh Ed25519 key
// is generated and the file is updated in-place.
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

	// Verify password before touching any identities.
	nonceLen := chacha20poly1305.NonceSizeX
	if len(f.Verify) <= nonceLen {
		return nil, fmt.Errorf("client: load keystore: missing or truncated verify field")
	}
	canary, err := ksDecrypt(masterKey, f.Verify[:nonceLen], f.Verify[nonceLen:])
	if err != nil || string(canary) != keystoreCanary {
		return nil, fmt.Errorf("client: load keystore: wrong password or corrupted data")
	}

	k := &Keystore{
		masterKey:  masterKey,
		salt:       f.Salt,
		kdfTime:    f.KDFTime,
		kdfMemory:  f.KDFMemory,
		kdfThreads: f.KDFThreads,
	}

	migrated := false
	for _, rec := range f.Identities {
		privBytes, err := ksDecrypt(masterKey, rec.Nonce, rec.Ciphertext)
		if err != nil {
			return nil, fmt.Errorf("client: load keystore: wrong password or corrupted data")
		}
		privKey, err := ecdh.X25519().NewPrivateKey(privBytes)
		if err != nil {
			return nil, fmt.Errorf("client: load keystore: invalid key %q: %w", rec.Name, err)
		}

		var signKey ed25519.PrivateKey
		if len(rec.SignNonce) > 0 && len(rec.SignCiphertext) > 0 {
			signBytes, err := ksDecrypt(masterKey, rec.SignNonce, rec.SignCiphertext)
			if err != nil {
				return nil, fmt.Errorf("client: load keystore: wrong password or corrupted data")
			}
			signKey = ed25519.PrivateKey(signBytes)
		} else {
			_, signKey, err = ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return nil, fmt.Errorf("client: load keystore: generate sign key: %w", err)
			}
			migrated = true
		}

		k.identities = append(k.identities, &Identity{Name: rec.Name, Key: privKey, SignKey: signKey})
	}

	if migrated {
		if err := k.Save(path); err != nil {
			return nil, fmt.Errorf("client: load keystore: persist migrated sign keys: %w", err)
		}
	}

	for _, rec := range f.Channels {
		keyBytes, err := ksDecrypt(masterKey, rec.Nonce, rec.Ciphertext)
		if err != nil {
			return nil, fmt.Errorf("client: load keystore: wrong password or corrupted channel %q", rec.Name)
		}
		if len(keyBytes) != 32 {
			return nil, fmt.Errorf("client: load keystore: invalid channel key length for %q", rec.Name)
		}
		ch := &Channel{Name: rec.Name}
		copy(ch.Key[:], keyBytes)
		k.channels = append(k.channels, ch)
	}

	return k, nil
}

// Save encrypts all identities and writes the keystore to path.
// The file is written atomically via a temp file so a crash mid-write
// never leaves a truncated keystore.
func (k *Keystore) Save(path string) error {
	vNonce, vCT, err := ksEncrypt(k.masterKey, []byte(keystoreCanary))
	if err != nil {
		return fmt.Errorf("client: save keystore: write verify canary: %w", err)
	}
	f := keystoreFile{
		Version:    keystoreVersion,
		Salt:       k.salt,
		KDFTime:    k.kdfTime,
		KDFMemory:  k.kdfMemory,
		KDFThreads: k.kdfThreads,
		Verify:     append(vNonce, vCT...),
	}

	for _, id := range k.identities {
		nonce, ct, err := ksEncrypt(k.masterKey, id.Key.Bytes())
		if err != nil {
			return fmt.Errorf("client: save keystore: encrypt %q: %w", id.Name, err)
		}
		rec := identityRecord{
			Name:       id.Name,
			Nonce:      nonce,
			Ciphertext: ct,
		}
		if len(id.SignKey) > 0 {
			sNonce, sCT, err := ksEncrypt(k.masterKey, id.SignKey)
			if err != nil {
				return fmt.Errorf("client: save keystore: encrypt sign key %q: %w", id.Name, err)
			}
			rec.SignNonce = sNonce
			rec.SignCiphertext = sCT
		}
		f.Identities = append(f.Identities, rec)
	}

	for _, ch := range k.channels {
		nonce, ct, err := ksEncrypt(k.masterKey, ch.Key[:])
		if err != nil {
			return fmt.Errorf("client: save keystore: encrypt channel %q: %w", ch.Name, err)
		}
		f.Channels = append(f.Channels, channelRecord{
			Name:       ch.Name,
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

// Add generates a fresh identity under name and returns it.
// Returns an error if name is already taken.
func (k *Keystore) Add(name string) (*Identity, error) {
	if k.get(name) != nil {
		return nil, fmt.Errorf("client: identity %q already exists", name)
	}
	privKey, err := GenerateKey()
	if err != nil {
		return nil, err
	}
	_, signKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	id := &Identity{Name: name, Key: privKey, SignKey: signKey}
	k.identities = append(k.identities, id)
	return id, nil
}

// Import stores an existing private key under name.
// Returns an error if name is already taken.
func (k *Keystore) Import(name string, privKey *ecdh.PrivateKey) error {
	if k.get(name) != nil {
		return fmt.Errorf("client: identity %q already exists", name)
	}
	_, signKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	k.identities = append(k.identities, &Identity{Name: name, Key: privKey, SignKey: signKey})
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

// GetIdentity returns the named identity, or nil if not found.
func (k *Keystore) GetIdentity(name string) *Identity {
	return k.get(name)
}

// Keys returns the X25519 private key for every stored identity, suitable for
// passing to client.New for multi-identity scraping.
func (k *Keystore) Keys() []*ecdh.PrivateKey {
	keys := make([]*ecdh.PrivateKey, len(k.identities))
	for i, id := range k.identities {
		keys[i] = id.Key
	}
	return keys
}

// AddChannel derives a 32-byte channel key from passphrase and stores it under name.
// Returns an error if name is already taken.
func (k *Keystore) AddChannel(name, passphrase string) (*Channel, error) {
	if k.getChannel(name) != nil {
		return nil, fmt.Errorf("client: channel %q already exists", name)
	}
	ch := &Channel{
		Name: name,
		Key:  sha256.Sum256([]byte(passphrase)),
	}
	k.channels = append(k.channels, ch)
	return ch, nil
}

// RemoveChannel removes the channel with the given name.
// Returns false if not found.
func (k *Keystore) RemoveChannel(name string) bool {
	for i, ch := range k.channels {
		if ch.Name == name {
			k.channels = append(k.channels[:i], k.channels[i+1:]...)
			return true
		}
	}
	return false
}

// ListChannels returns all stored channels (names only; keys are in-memory secrets).
func (k *Keystore) ListChannels() []*Channel {
	out := make([]*Channel, len(k.channels))
	copy(out, k.channels)
	return out
}

// Channels returns a copy of all channel keys suitable for passing to client.New.
func (k *Keystore) Channels() []Channel {
	out := make([]Channel, len(k.channels))
	for i, ch := range k.channels {
		out[i] = *ch
	}
	return out
}

func (k *Keystore) getChannel(name string) *Channel {
	for _, ch := range k.channels {
		if ch.Name == name {
			return ch
		}
	}
	return nil
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

// keystoreCanary is the plaintext encrypted as a password-verification sentinel.
const keystoreCanary = "sneakernet-keystore-v1"

type keystoreFile struct {
	Version    int              `json:"version"`
	Salt       []byte           `json:"salt"`
	KDFTime    uint32           `json:"kdf_time"`
	KDFMemory  uint32           `json:"kdf_memory"`
	KDFThreads uint8            `json:"kdf_threads"`
	// Verify holds nonce || ciphertext of keystoreCanary under the master key.
	// Decryption failure on load means wrong password.
	Verify     []byte           `json:"verify"`
	Identities []identityRecord `json:"identities"`
	Channels   []channelRecord  `json:"channels,omitempty"`
}

type identityRecord struct {
	Name           string `json:"name"`
	Nonce          []byte `json:"nonce"`
	Ciphertext     []byte `json:"ciphertext"`
	SignNonce      []byte `json:"sign_nonce,omitempty"`
	SignCiphertext []byte `json:"sign_ciphertext,omitempty"`
}

type channelRecord struct {
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
