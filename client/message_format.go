package client

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
)

// v2 plaintext layout (plaintextSize bytes total):
//
//	[0:4]     magic "SNK\x02"
//	[4]       msg_type
//	[5]       flags  (bit0 = FlagIsFragment)
//	[6:14]    timestamp int64 LE (Unix seconds; 0 = unknown)
//	[14:46]   sender_ed25519_pub (32 bytes; all-zeros = anonymous)
//	[46:110]  signature (64 bytes; all-zeros = unsigned)
//	[110:366] thread_refs[8] (8×32 bytes skip list; all-zeros entry = absent)
//	[366:398] frag_id (32 bytes; all-zeros = single block)
//	[398:400] frag_index uint16 LE
//	[400:402] frag_total uint16 LE (1 = single block)
//	[402:404] content_len uint16 LE
//	[404:]    content + zero padding
// MagicV2 is the 4-byte header identifying a v2 encrypted message plaintext.
var MagicV2 = [4]byte{'S', 'N', 'K', 0x02}

const (
	MsgTypeText   uint8 = 0
	MsgTypeBinary uint8 = 1
	MsgTypeSystem uint8 = 2

	FlagIsFragment uint8 = 0x01

	v2ThreadCount = 8
	V2HeaderSize  = 404
	V2MaxContent  = plaintextSize - V2HeaderSize // 3620 with 4096-byte blocks
)

var (
	ErrNotV2        = errors.New("message_format: not a v2 payload")
	ErrMalformed    = errors.New("message_format: malformed payload")
	ErrContentTooLarge = errors.New("message_format: content exceeds V2MaxContent")
)

// MessagePayload is the decoded in-memory representation of a v2 plaintext.
type MessagePayload struct {
	MsgType    uint8
	Flags      uint8
	Timestamp  int64          // Unix seconds; 0 = unknown
	SenderPub  [32]byte       // Ed25519 public key; all-zeros = anonymous
	Signature  [64]byte       // all-zeros = unsigned
	ThreadRefs [8][32]byte    // skip list; refs[k] ≈ 2^k messages back; all-zeros = absent
	FragID     [32]byte       // all-zeros = not fragmented
	FragIndex  uint16
	FragTotal  uint16         // 1 = single block
	Content    []byte
}

// IsFragment reports whether the FlagIsFragment bit is set.
func (p MessagePayload) IsFragment() bool { return p.Flags&FlagIsFragment != 0 }

// IsAnonymous reports whether SenderPub is all-zeros.
func (p MessagePayload) IsAnonymous() bool { return p.SenderPub == [32]byte{} }

// EncodePayload serialises p into a fixed-size plaintext buffer.
func EncodePayload(p MessagePayload) ([plaintextSize]byte, error) {
	if len(p.Content) > V2MaxContent {
		return [plaintextSize]byte{}, ErrContentTooLarge
	}
	var buf [plaintextSize]byte
	copy(buf[0:4], MagicV2[:])
	buf[4] = p.MsgType
	flags := p.Flags
	if p.FragTotal > 1 {
		flags |= FlagIsFragment
	}
	buf[5] = flags
	binary.LittleEndian.PutUint64(buf[6:14], uint64(p.Timestamp))
	copy(buf[14:46], p.SenderPub[:])
	copy(buf[46:110], p.Signature[:])
	for i := 0; i < v2ThreadCount; i++ {
		copy(buf[110+i*32:110+(i+1)*32], p.ThreadRefs[i][:])
	}
	copy(buf[366:398], p.FragID[:])
	binary.LittleEndian.PutUint16(buf[398:400], p.FragIndex)
	binary.LittleEndian.PutUint16(buf[400:402], p.FragTotal)
	binary.LittleEndian.PutUint16(buf[402:404], uint16(len(p.Content)))
	copy(buf[404:], p.Content)
	return buf, nil
}

// DecodePayload parses a plaintext buffer produced by EncodePayload.
// Returns ErrNotV2 if the magic bytes do not match, ErrMalformed if
// content_len exceeds V2MaxContent.
func DecodePayload(plain [plaintextSize]byte) (MessagePayload, error) {
	if [4]byte(plain[0:4]) != MagicV2 {
		return MessagePayload{}, ErrNotV2
	}
	var p MessagePayload
	p.MsgType = plain[4]
	p.Flags = plain[5]
	p.Timestamp = int64(binary.LittleEndian.Uint64(plain[6:14]))
	copy(p.SenderPub[:], plain[14:46])
	copy(p.Signature[:], plain[46:110])
	for i := 0; i < v2ThreadCount; i++ {
		copy(p.ThreadRefs[i][:], plain[110+i*32:110+(i+1)*32])
	}
	copy(p.FragID[:], plain[366:398])
	p.FragIndex = binary.LittleEndian.Uint16(plain[398:400])
	p.FragTotal = binary.LittleEndian.Uint16(plain[400:402])
	contentLen := int(binary.LittleEndian.Uint16(plain[402:404]))
	if contentLen > V2MaxContent {
		return MessagePayload{}, ErrMalformed
	}
	p.Content = make([]byte, contentLen)
	copy(p.Content, plain[404:404+contentLen])
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
	for i := 1; i < v2ThreadCount; i++ {
		refs[i] = prevRefs[i-1]
	}
	return refs
}
