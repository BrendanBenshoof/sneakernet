package client

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
)

// v3 plaintext layout (plaintextSize bytes total):
//
//	[0:4]     magic "SNK\x03"
//	[4]       msg_type
//	[5]       flags (reserved; must be zero)
//	[6:14]    timestamp int64 LE (Unix seconds; 0 = unknown)
//	[14:46]   sender_ed25519_pub (32 bytes; all-zeros = anonymous)
//	[46:110]  signature (64 bytes; all-zeros = unsigned)
//	[110:366] thread_refs[8] (8×32 bytes skip list; all-zeros entry = absent)
//	[366:368] content_len uint16 LE
//	[368:]    content + zero padding

// MagicV3 is the 4-byte header identifying a v3 encrypted message plaintext.
var MagicV3 = [4]byte{'S', 'N', 'K', 0x03}

const (
	MsgTypeText   uint8 = 0
	MsgTypeBinary uint8 = 1
	MsgTypeSystem uint8 = 2
	MsgTypePost   uint8 = 3 // forum post; content is "subject\nbody"
	MsgTypeEdit   uint8 = 4 // edit: content is "<64-hex target block id>\n<new content>"
	MsgTypeDelete uint8 = 5 // delete: content is "<64-hex target block id>"

	threadCount  = 8
	V3HeaderSize = 368
	V3MaxContent = plaintextSize - V3HeaderSize // 3656 with 4096-byte blocks
)

var (
	ErrNotV3           = errors.New("message_format: not a v3 payload")
	ErrMalformed       = errors.New("message_format: malformed payload")
	ErrContentTooLarge = errors.New("message_format: content exceeds V3MaxContent")
)

// MessagePayload is the decoded in-memory representation of a v3 plaintext.
type MessagePayload struct {
	MsgType    uint8
	Flags      uint8
	Timestamp  int64       // Unix seconds; 0 = unknown
	SenderPub  [32]byte    // Ed25519 public key; all-zeros = anonymous
	Signature  [64]byte    // all-zeros = unsigned
	ThreadRefs [8][32]byte // skip list; refs[k] ≈ 2^k messages back; all-zeros = absent
	Content    []byte

	// Channel is set by tryAllKeys to the channel name used to decrypt this
	// payload. Empty for direct messages. Not part of the wire format.
	Channel string

	// SentTo is the raw X25519 public key of the recipient. Set by handleSend
	// when storing a sent message immediately, so it appears without a scrape.
	// Not part of the wire format.
	SentTo []byte

	// DecryptedBy is the local identity name that decrypted (or sent) this
	// message. Set by Scrape (from tryAllKeys) and by handleSend. Not part of
	// the wire format.
	DecryptedBy string
}

// IsAnonymous reports whether SenderPub is all-zeros.
func (p MessagePayload) IsAnonymous() bool { return p.SenderPub == [32]byte{} }

// EncodePayload serialises p into a fixed-size plaintext buffer.
func EncodePayload(p MessagePayload) ([plaintextSize]byte, error) {
	if len(p.Content) > V3MaxContent {
		return [plaintextSize]byte{}, ErrContentTooLarge
	}
	var buf [plaintextSize]byte
	copy(buf[0:4], MagicV3[:])
	buf[4] = p.MsgType
	buf[5] = p.Flags
	binary.LittleEndian.PutUint64(buf[6:14], uint64(p.Timestamp))
	copy(buf[14:46], p.SenderPub[:])
	copy(buf[46:110], p.Signature[:])
	for i := 0; i < threadCount; i++ {
		copy(buf[110+i*32:110+(i+1)*32], p.ThreadRefs[i][:])
	}
	binary.LittleEndian.PutUint16(buf[366:368], uint16(len(p.Content)))
	copy(buf[368:], p.Content)
	return buf, nil
}

// DecodePayload parses a plaintext buffer produced by EncodePayload.
// Returns ErrNotV3 if the magic bytes do not match, ErrMalformed if
// content_len exceeds V3MaxContent.
func DecodePayload(plain [plaintextSize]byte) (MessagePayload, error) {
	if [4]byte(plain[0:4]) != MagicV3 {
		return MessagePayload{}, ErrNotV3
	}
	var p MessagePayload
	p.MsgType = plain[4]
	p.Flags = plain[5]
	p.Timestamp = int64(binary.LittleEndian.Uint64(plain[6:14]))
	copy(p.SenderPub[:], plain[14:46])
	copy(p.Signature[:], plain[46:110])
	for i := 0; i < threadCount; i++ {
		copy(p.ThreadRefs[i][:], plain[110+i*32:110+(i+1)*32])
	}
	contentLen := int(binary.LittleEndian.Uint16(plain[366:368]))
	if contentLen > V3MaxContent {
		return MessagePayload{}, ErrMalformed
	}
	p.Content = make([]byte, contentLen)
	copy(p.Content, plain[368:368+contentLen])
	return p, nil
}

// SignPayload signs the entire plaintext buffer in-place using sigKey.
// Bytes [46:110] (the signature field) are zeroed before signing so the
// signature is deterministic and self-consistent.
func SignPayload(plain *[plaintextSize]byte, sigKey ed25519.PrivateKey) {
	for i := 46; i < 110; i++ {
		plain[i] = 0
	}
	sig := ed25519.Sign(sigKey, plain[:])
	copy(plain[46:110], sig)
}

// VerifySignature verifies the Ed25519 signature embedded in plain.
// Returns false if SenderPub is all-zeros (anonymous) or the signature
// does not validate.
func VerifySignature(plain [plaintextSize]byte) bool {
	var zeroPub [32]byte
	if [32]byte(plain[14:46]) == zeroPub {
		return false
	}
	var sig [64]byte
	copy(sig[:], plain[46:110])
	// Zero the signature field before verifying
	for i := 46; i < 110; i++ {
		plain[i] = 0
	}
	pub := ed25519.PublicKey(plain[14:46])
	return ed25519.Verify(pub, plain[:], sig[:])
}

// BuildThreadRefs constructs a new skip list for a reply to a message whose
// thread refs are prevRefs. The direct reply target is target.
func BuildThreadRefs(target [32]byte, prevRefs [8][32]byte) [8][32]byte {
	var refs [8][32]byte
	refs[0] = target
	for i := 1; i < threadCount; i++ {
		refs[i] = prevRefs[i-1]
	}
	return refs
}
