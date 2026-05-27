package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"unicode"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	kdfSaltSize        = 32
	kdfTime    uint32  = 2
	kdfMemory  uint32  = 64 * 1024 // 64 MB
	kdfThreads uint8   = 4
	kdfKeyLen  uint32  = 32

	keystoreVersion = 2
)

// Identity is a named key pair held in a Keystore.
// SignKey is the Ed25519 private key; the X25519 key for encryption is derived
// from it on demand via EdPubToX25519 / edPrivToX25519.
type Identity struct {
	Name    string
	SignKey ed25519.PrivateKey
}

// PublicKey returns the Ed25519 public key for this identity.
// This is the single key shared with contacts for both verification and encryption.
func (id *Identity) PublicKey() ed25519.PublicKey {
	return id.SignKey.Public().(ed25519.PublicKey)
}

// Channel is a named symmetric channel key. Anyone who knows the passphrase
// (from which Key is derived) can decrypt and post to the channel anonymously.
type Channel struct {
	Name string
	Key  [32]byte
}

// Contact is a named remote identity — public key only, no private key.
// PublicKey is the Ed25519 public key, which serves as both the encryption
// address (via EdPubToX25519) and the signing verification key.
// Contacts are stored plaintext in the keystore file because they are not secrets.
type Contact struct {
	Name      string
	PublicKey []byte // raw 32-byte Ed25519 public key
}

// validateName enforces shared name rules for identities and contacts:
// 1–64 Unicode characters, no '/' (URI delimiter), no control characters.
func validateName(name string) error {
	runes := []rune(name)
	if len(runes) == 0 {
		return fmt.Errorf("client: name must not be empty")
	}
	if len(runes) > 64 {
		return fmt.Errorf("client: name must not exceed 64 characters")
	}
	for _, r := range runes {
		if r == '/' || unicode.IsControl(r) {
			return fmt.Errorf("client: name contains invalid character")
		}
	}
	return nil
}

// Keystore is a password-protected collection of named identities, channel keys,
// and contacts. Load it once at startup; all private keys are decrypted into memory.
type Keystore struct {
	masterKey  [kdfKeyLen]byte
	salt       []byte
	kdfTime    uint32
	kdfMemory  uint32
	kdfThreads uint8
	identities []*Identity
	channels   []*Channel
	contacts   []*Contact
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
// Version 1 keystores are migrated automatically: the Ed25519 signing key is kept
// as the unified identity key, and the separate X25519 key is discarded.
func LoadKeystore(path string, password []byte) (*Keystore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("client: load keystore: %w", err)
	}

	var f keystoreFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("client: load keystore: %w", err)
	}
	if f.Version != 1 && f.Version != keystoreVersion {
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

	needsSave := f.Version < keystoreVersion
	for _, rec := range f.Identities {
		var signKey ed25519.PrivateKey
		if len(rec.SignNonce) > 0 && len(rec.SignCiphertext) > 0 {
			// v1 identity with a signing key, or v2 identity: use it directly.
			signBytes, err := ksDecrypt(masterKey, rec.SignNonce, rec.SignCiphertext)
			if err != nil {
				return nil, fmt.Errorf("client: load keystore: wrong password or corrupted data")
			}
			signKey = ed25519.PrivateKey(signBytes)
		} else {
			// v1 identity without a signing key: generate a fresh one.
			// The old X25519 key is discarded; contacts must re-exchange keys.
			_, signKey, err = ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return nil, fmt.Errorf("client: load keystore: generate sign key: %w", err)
			}
			needsSave = true
		}
		k.identities = append(k.identities, &Identity{Name: rec.Name, SignKey: signKey})
	}

	if needsSave {
		if err := k.Save(path); err != nil {
			return nil, fmt.Errorf("client: load keystore: persist migration: %w", err)
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

	for _, rec := range f.Contacts {
		// v1 contacts stored PublicKey (X25519) + SigningPublicKey (Ed25519).
		// Migrate by using SigningPublicKey as the unified PublicKey.
		// v2 contacts store only PublicKey (Ed25519).
		pub := rec.PublicKey
		if len(rec.SigningPublicKey) == 32 {
			pub = rec.SigningPublicKey
		}
		if len(pub) != 32 {
			continue // skip malformed entries
		}
		k.contacts = append(k.contacts, &Contact{
			Name:      rec.Name,
			PublicKey: pub,
		})
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
		// Store the Ed25519 private key in the sign_nonce/sign_ciphertext fields.
		// The nonce/ciphertext fields are left empty in v2 (no separate X25519 key).
		sNonce, sCT, err := ksEncrypt(k.masterKey, id.SignKey)
		if err != nil {
			return fmt.Errorf("client: save keystore: encrypt %q: %w", id.Name, err)
		}
		f.Identities = append(f.Identities, identityRecord{
			Name:           id.Name,
			SignNonce:      sNonce,
			SignCiphertext: sCT,
		})
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

	for _, c := range k.contacts {
		f.Contacts = append(f.Contacts, contactRecord{
			Name:      c.Name,
			PublicKey: c.PublicKey,
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

// Add generates a fresh Ed25519 identity under name and returns it.
// Returns an error if the name is invalid or already taken.
func (k *Keystore) Add(name string) (*Identity, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	if k.get(name) != nil {
		return nil, fmt.Errorf("client: identity %q already exists", name)
	}
	_, signKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	id := &Identity{Name: name, SignKey: signKey}
	k.identities = append(k.identities, id)
	return id, nil
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


// Identities returns all stored identities. Prefer this over Keys() when the
// identity name is needed (e.g. to set decrypted_by on saved messages).
func (k *Keystore) Identities() []*Identity {
	ids := make([]*Identity, len(k.identities))
	copy(ids, k.identities)
	return ids
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

// AddContact stores a new contact by their Ed25519 public key.
// Names may repeat; public keys must be unique.
func (k *Keystore) AddContact(name string, pubKey []byte) (*Contact, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	if len(pubKey) != 32 {
		return nil, fmt.Errorf("client: invalid public key length")
	}
	for _, c := range k.contacts {
		if bytes.Equal(c.PublicKey, pubKey) {
			return nil, fmt.Errorf("client: contact with that public key already exists")
		}
	}
	c := &Contact{
		Name:      name,
		PublicKey: append([]byte(nil), pubKey...),
	}
	k.contacts = append(k.contacts, c)
	return c, nil
}

// RemoveContact removes the contact with the matching public key.
func (k *Keystore) RemoveContact(pubKey []byte) bool {
	for i, c := range k.contacts {
		if bytes.Equal(c.PublicKey, pubKey) {
			k.contacts = append(k.contacts[:i], k.contacts[i+1:]...)
			return true
		}
	}
	return false
}

// RenameContact updates the display name of the contact identified by pubKey.
// Returns (true, nil) on success, (false, nil) if not found, (false, err) on invalid name.
func (k *Keystore) RenameContact(pubKey []byte, newName string) (bool, error) {
	if err := validateName(newName); err != nil {
		return false, err
	}
	for _, c := range k.contacts {
		if bytes.Equal(c.PublicKey, pubKey) {
			c.Name = newName
			return true, nil
		}
	}
	return false, nil
}

// ListContacts returns a copy of all stored contacts.
func (k *Keystore) ListContacts() []*Contact {
	out := make([]*Contact, len(k.contacts))
	copy(out, k.contacts)
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

// VerifyPassword returns true if password re-derives the same master key.
func (k *Keystore) VerifyPassword(password []byte) bool {
	derived := deriveKey(password, k.salt, k.kdfTime, k.kdfMemory, k.kdfThreads)
	return subtle.ConstantTimeCompare(derived[:], k.masterKey[:]) == 1
}

// IdentityExport is the portable, password-encrypted bundle produced by ExportIdentity.
type IdentityExport struct {
	Version    int    `json:"version"`
	Name       string `json:"name"`
	Salt       []byte `json:"salt"`
	KDFTime    uint32 `json:"kdf_time"`
	KDFMemory  uint32 `json:"kdf_memory"`
	KDFThreads uint8  `json:"kdf_threads"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// ExportIdentity encrypts the named identity's Ed25519 private key with
// exportPassword (fresh random salt, same Argon2id params) and returns
// the JSON-encoded IdentityExport bundle.
func (k *Keystore) ExportIdentity(name string, exportPassword []byte) ([]byte, error) {
	id := k.get(name)
	if id == nil {
		return nil, fmt.Errorf("client: identity %q not found", name)
	}
	salt := make([]byte, kdfSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	exportKey := deriveKey(exportPassword, salt, kdfTime, kdfMemory, kdfThreads)
	nonce, ct, err := ksEncrypt(exportKey, id.SignKey)
	if err != nil {
		return nil, err
	}
	return json.Marshal(IdentityExport{
		Version: 1, Name: id.Name,
		Salt: salt, KDFTime: kdfTime, KDFMemory: kdfMemory, KDFThreads: kdfThreads,
		Nonce: nonce, Ciphertext: ct,
	})
}

// ImportIdentity decrypts an IdentityExport bundle with exportPassword and
// appends the identity to the keystore. Returns an error if the name is
// already taken or the password is wrong.
func (k *Keystore) ImportIdentity(data []byte, exportPassword []byte) (*Identity, error) {
	var b IdentityExport
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("client: import identity: invalid bundle")
	}
	if b.Version != 1 {
		return nil, fmt.Errorf("client: import identity: unsupported version %d", b.Version)
	}
	exportKey := deriveKey(exportPassword, b.Salt, b.KDFTime, b.KDFMemory, b.KDFThreads)
	privBytes, err := ksDecrypt(exportKey, b.Nonce, b.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("client: import identity: wrong password or corrupted bundle")
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("client: import identity: invalid key size")
	}
	if err := validateName(b.Name); err != nil {
		return nil, err
	}
	if k.get(b.Name) != nil {
		return nil, fmt.Errorf("client: identity %q already exists", b.Name)
	}
	id := &Identity{Name: b.Name, SignKey: ed25519.PrivateKey(privBytes)}
	k.identities = append(k.identities, id)
	return id, nil
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
	// Contacts are public-key-only records; stored plaintext (not encrypted).
	Contacts   []contactRecord  `json:"contacts,omitempty"`
}

type identityRecord struct {
	Name           string `json:"name"`
	// Nonce/Ciphertext held the v1 X25519 key; unused in v2 but kept for migration reads.
	Nonce          []byte `json:"nonce,omitempty"`
	Ciphertext     []byte `json:"ciphertext,omitempty"`
	// SignNonce/SignCiphertext hold the Ed25519 private key (v1 and v2).
	SignNonce      []byte `json:"sign_nonce,omitempty"`
	SignCiphertext []byte `json:"sign_ciphertext,omitempty"`
}

type channelRecord struct {
	Name       string `json:"name"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

type contactRecord struct {
	Name            string `json:"name"`
	PublicKey       []byte `json:"public_key"`
	// SigningPublicKey is present in v1 contacts only; used for migration.
	SigningPublicKey []byte `json:"signing_public_key,omitempty"`
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
