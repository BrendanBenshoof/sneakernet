package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/brendanbenshoof/sneakernet/blockstore"
	"github.com/brendanbenshoof/sneakernet/client"
)

// POST /api/keystore/create  {"password":"..."}
// Creates a new keystore file. Returns 409 if one already exists.
func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Password == "" {
		writeError(w, http.StatusBadRequest, "password required")
		return
	}
	if _, err := os.Stat(s.ksPath); err == nil {
		writeError(w, http.StatusConflict, "keystore already exists; use /api/unlock")
		return
	}
	ks, err := client.NewKeystore([]byte(req.Password))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create keystore")
		return
	}
	if err := ks.Save(s.ksPath); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save keystore")
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// POST /api/unlock  {"password":"..."}
// Derives the master key, loads all identities, and returns a session token.
// Returns 404 if no keystore file exists, 401 on wrong password.
func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}

	// LoadKeystore runs Argon2id — call without holding the lock.
	ks, err := client.LoadKeystore(s.ksPath, []byte(req.Password))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, "keystore not found; call /api/keystore/create first")
		} else {
			writeError(w, http.StatusUnauthorized, "invalid password or corrupted keystore")
		}
		return
	}

	token, err := newToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token generation failed")
		return
	}

	s.mu.Lock()
	s.ks = ks
	s.tokens[token] = struct{}{}
	s.rebuildScraper()
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

// POST /api/lock
// Clears all session tokens and wipes keys from memory.
func (s *Server) handleLock(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.ks = nil
	s.scraper = nil
	s.tokens = make(map[string]struct{})
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// GET /api/identities
// Returns all stored identities with their Ed25519 public key (used for both
// message verification and encryption address).
func (s *Server) handleListIdentities(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	ids := s.ks.List()
	s.mu.RUnlock()

	type identityResp struct {
		Name      string `json:"name"`
		PublicKey string `json:"public_key"`
	}
	out := make([]identityResp, len(ids))
	for i, id := range ids {
		out[i] = identityResp{
			Name:      id.Name,
			PublicKey: base64.StdEncoding.EncodeToString(id.PublicKey()),
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// POST /api/identities  {"name":"alice"}
// Generates a new identity, saves the keystore, and returns the public keys.
func (s *Server) handleAddIdentity(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	id, err := s.ks.Add(req.Name)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err := s.ks.Save(s.ksPath); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save keystore")
		return
	}
	s.rebuildScraper()

	writeJSON(w, http.StatusCreated, map[string]string{
		"name":       req.Name,
		"public_key": base64.StdEncoding.EncodeToString(id.PublicKey()),
	})
}

// DELETE /api/identities/{name}
// Removes the named identity, saves the keystore.
func (s *Server) handleRemoveIdentity(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.ks.Remove(name) {
		writeError(w, http.StatusNotFound, "identity not found")
		return
	}
	if err := s.ks.Save(s.ksPath); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save keystore")
		return
	}
	s.rebuildScraper()

	w.WriteHeader(http.StatusNoContent)
}

type msgResp struct {
	ID          int64    `json:"id"`
	BlockID     string   `json:"block_id"`
	SenderPub   string   `json:"sender_pub"`
	ThreadRefs  []string `json:"thread_refs"`
	SentAt      string   `json:"sent_at,omitempty"`
	MsgType     uint8    `json:"msg_type"`
	Content     string   `json:"content"`
	Channel     string   `json:"channel,omitempty"`
	ReceivedAt  string   `json:"received_at"`
	SentTo      string   `json:"sent_to,omitempty"`      // base64 Ed25519 pub of recipient; set for sent messages
	DecryptedBy string   `json:"decrypted_by,omitempty"` // local identity name that decrypted or sent the message
}

func buildMsgResp(m client.Message) msgResp {
	resp := msgResp{
		ID:         m.ID,
		BlockID:    hex.EncodeToString(m.BlockID[:]),
		Content:    base64.StdEncoding.EncodeToString(m.Content),
		Channel:    m.Channel,
		ReceivedAt: m.ReceivedAt.UTC().Format(time.RFC3339),
		MsgType:    m.MsgType,
	}
	if m.SenderPub != ([32]byte{}) {
		resp.SenderPub = base64.StdEncoding.EncodeToString(m.SenderPub[:])
	}
	if !m.SentAt.IsZero() {
		resp.SentAt = m.SentAt.UTC().Format(time.RFC3339)
	}
	var refs []string
	last := -1
	var zero [32]byte
	for j, ref := range m.ThreadRefs {
		if ref != zero {
			last = j
		}
	}
	for j := 0; j <= last; j++ {
		refs = append(refs, hex.EncodeToString(m.ThreadRefs[j][:]))
	}
	if refs == nil {
		refs = []string{}
	}
	resp.ThreadRefs = refs
	if len(m.SentTo) > 0 {
		resp.SentTo = base64.StdEncoding.EncodeToString(m.SentTo)
	}
	resp.DecryptedBy = m.DecryptedBy
	return resp
}

// GET /api/messages?after_id=N
// Returns messages with id > after_id (default 0).
func (s *Server) handleListMessages(w http.ResponseWriter, r *http.Request) {
	afterID, _ := strconv.ParseInt(r.URL.Query().Get("after_id"), 10, 64)

	msgs, err := s.msgs.ListMessagesAfter(afterID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list messages")
		return
	}

	out := make([]msgResp, len(msgs))
	for i, m := range msgs {
		out[i] = buildMsgResp(m)
	}
	writeJSON(w, http.StatusOK, out)
}

// GET /api/messages/{block_id}
// Returns a single message by its block ID (hex).
func (s *Server) handleGetMessage(w http.ResponseWriter, r *http.Request) {
	blockIDBytes, err := hex.DecodeString(r.PathValue("block_id"))
	if err != nil || len(blockIDBytes) != blockstore.IDSize {
		writeError(w, http.StatusBadRequest, "invalid block_id")
		return
	}
	var blockID blockstore.ID
	copy(blockID[:], blockIDBytes)

	m, found, err := s.msgs.GetMessage(blockID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to retrieve message")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "message not found")
		return
	}
	writeJSON(w, http.StatusOK, buildMsgResp(m))
}

// POST /api/scrape
// Scans all new blocks and attempts decryption with every stored identity.
func (s *Server) handleScrape(w http.ResponseWriter, r *http.Request) {
	s.scrapeMu.Lock()
	defer s.scrapeMu.Unlock()

	s.mu.RLock()
	scraper := s.scraper
	s.mu.RUnlock()

	found, err := scraper.Scrape(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "scrape failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"found": found})
}

// POST /api/send
//
//	{
//	  "recipient_public_key": "<base64 Ed25519>",
//	  "message": "<text>",
//	  "sender_identity": "<name>",          // optional; omit = anonymous
//	  "reply_to_block_id": "<hex block ID>" // optional; omit = new thread
//	}
//
// Encrypts and stores one or more blocks. Returns:
//
//	{"block_ids": ["<hex>", ...], "frag_id": "<hex>"}
//
// frag_id is the empty string for single-block messages.
func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RecipientPublicKey string `json:"recipient_public_key"`
		Message            string `json:"message"`
		SenderIdentity     string `json:"sender_identity"`
		ReplyToBlockID     string `json:"reply_to_block_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.RecipientPublicKey == "" || req.Message == "" {
		writeError(w, http.StatusBadRequest, "recipient_public_key and message required")
		return
	}

	recipientEdPubBytes, err := base64.StdEncoding.DecodeString(req.RecipientPublicKey)
	if err != nil || len(recipientEdPubBytes) != 32 {
		writeError(w, http.StatusBadRequest, "invalid recipient_public_key encoding")
		return
	}
	recipientEdPub := ed25519.PublicKey(recipientEdPubBytes)

	// Resolve optional sender identity.
	s.mu.RLock()
	ks := s.ks
	s.mu.RUnlock()

	var mp client.MessagePayload
	mp.MsgType = client.MsgTypeText
	mp.Timestamp = time.Now().Unix()

	var signerID *client.Identity
	if req.SenderIdentity != "" {
		signerID = ks.GetIdentity(req.SenderIdentity)
		if signerID == nil {
			writeError(w, http.StatusBadRequest, "sender_identity not found")
			return
		}
		copy(mp.SenderPub[:], signerID.PublicKey())
	}

	// Resolve optional thread refs from the replied-to message.
	if req.ReplyToBlockID != "" {
		replyIDBytes, err := hex.DecodeString(req.ReplyToBlockID)
		if err != nil || len(replyIDBytes) != blockstore.IDSize {
			writeError(w, http.StatusBadRequest, "invalid reply_to_block_id")
			return
		}
		var replyID blockstore.ID
		copy(replyID[:], replyIDBytes)

		if m, found, err := s.msgs.GetMessage(replyID); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to look up reply target")
			return
		} else if found {
			mp.ThreadRefs = client.BuildThreadRefs(replyID, m.ThreadRefs)
		} else {
			// Reply target not in our store; set just the direct ref.
			mp.ThreadRefs[0] = replyID
		}
	}

	content := []byte(req.Message)
	if len(content) <= client.V2MaxContent {
		// Single block.
		mp.Content = content
		mp.FragTotal = 1

		var payload blockstore.Payload
		if signerID != nil {
			payload, err = client.EncryptSigned(recipientEdPub, mp, signerID.SignKey)
		} else {
			payload, err = client.Encrypt(recipientEdPub, mp)
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		var stamp blockstore.Stamp
		id, err := s.blocks.Put(stamp, payload)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to store block")
			return
		}

		// Immediately persist plaintext so it appears without waiting for a scrape.
		mp.SentTo = recipientEdPubBytes
		mp.DecryptedBy = req.SenderIdentity
		_, _ = s.msgs.SaveMessage(id, mp)

		writeJSON(w, http.StatusCreated, map[string]any{
			"block_ids": []string{hex.EncodeToString(id[:])},
			"frag_id":   "",
		})
		return
	}

	// Multi-block: split content into fragments.
	var fragID [32]byte
	if _, err := rand.Read(fragID[:]); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate fragment ID")
		return
	}

	chunks := splitBytes(content, client.V2MaxContent)
	total := uint16(len(chunks))
	blockIDs := make([]string, 0, total)
	var stamp blockstore.Stamp

	for i, chunk := range chunks {
		fmp := mp
		fmp.Content = chunk
		fmp.FragID = fragID
		fmp.FragIndex = uint16(i)
		fmp.FragTotal = total
		fmp.SentTo = recipientEdPubBytes
		fmp.DecryptedBy = req.SenderIdentity

		var payload blockstore.Payload
		if signerID != nil {
			payload, err = client.EncryptSigned(recipientEdPub, fmp, signerID.SignKey)
		} else {
			payload, err = client.Encrypt(recipientEdPub, fmp)
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to encrypt fragment")
			return
		}
		id, err := s.blocks.Put(stamp, payload)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to store fragment block")
			return
		}
		_, _ = s.msgs.SaveFragment(id, fmp)
		blockIDs = append(blockIDs, hex.EncodeToString(id[:]))
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"block_ids": blockIDs,
		"frag_id":   hex.EncodeToString(fragID[:]),
	})
}

// POST /api/keystore/change-password  {"new_password":"..."}
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NewPassword string `json:"new_password"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "new_password required")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ks.ChangePassword([]byte(req.NewPassword)); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to change password")
		return
	}
	if err := s.ks.Save(s.ksPath); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save keystore")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /api/channels
// Returns all stored channel names.
func (s *Server) handleListChannels(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	chs := s.ks.ListChannels()
	s.mu.RUnlock()

	type chanResp struct {
		Name string `json:"name"`
	}
	out := make([]chanResp, len(chs))
	for i, ch := range chs {
		out[i] = chanResp{Name: ch.Name}
	}
	writeJSON(w, http.StatusOK, out)
}

// POST /api/channels  {"name":"...", "passphrase":"..."}
// Derives a 32-byte channel key from passphrase, saves the keystore.
func (s *Server) handleAddChannel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string `json:"name"`
		Passphrase string `json:"passphrase"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Name == "" || req.Passphrase == "" {
		writeError(w, http.StatusBadRequest, "name and passphrase required")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.ks.AddChannel(req.Name, req.Passphrase); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err := s.ks.Save(s.ksPath); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save keystore")
		return
	}
	s.rebuildScraper()

	writeJSON(w, http.StatusCreated, map[string]string{"name": req.Name})
}

// DELETE /api/channels/{name}
// Removes the named channel key from the keystore.
func (s *Server) handleRemoveChannel(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.ks.RemoveChannel(name) {
		writeError(w, http.StatusNotFound, "channel not found")
		return
	}
	if err := s.ks.Save(s.ksPath); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save keystore")
		return
	}
	s.rebuildScraper()

	w.WriteHeader(http.StatusNoContent)
}

// POST /api/send-channel
//
//	{
//	  "channel_name": "...",
//	  "message": "...",
//	  "sender_identity": "<name>",          // optional; omit = anonymous
//	  "reply_to_block_id": "<hex block ID>" // optional; omit = new thread
//	}
//
// Encrypts message with the named channel key and stores the resulting block.
func (s *Server) handleSendChannel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ChannelName    string `json:"channel_name"`
		Message        string `json:"message"`
		SenderIdentity string `json:"sender_identity"`
		ReplyToBlockID string `json:"reply_to_block_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.ChannelName == "" || req.Message == "" {
		writeError(w, http.StatusBadRequest, "channel_name and message required")
		return
	}

	s.mu.RLock()
	ks := s.ks
	chs := s.ks.ListChannels()
	s.mu.RUnlock()

	var channelKey [32]byte
	found := false
	for _, ch := range chs {
		if ch.Name == req.ChannelName {
			channelKey = ch.Key
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "channel not found")
		return
	}

	mp := client.MessagePayload{
		MsgType:   client.MsgTypeText,
		FragTotal: 1,
		Timestamp: time.Now().Unix(),
		Content:   []byte(req.Message),
	}

	var signerID *client.Identity
	if req.SenderIdentity != "" {
		signerID = ks.GetIdentity(req.SenderIdentity)
		if signerID == nil {
			writeError(w, http.StatusBadRequest, "sender_identity not found")
			return
		}
		copy(mp.SenderPub[:], signerID.PublicKey())
	}

	if req.ReplyToBlockID != "" {
		replyIDBytes, err := hex.DecodeString(req.ReplyToBlockID)
		if err != nil || len(replyIDBytes) != blockstore.IDSize {
			writeError(w, http.StatusBadRequest, "invalid reply_to_block_id")
			return
		}
		var replyID blockstore.ID
		copy(replyID[:], replyIDBytes)
		if m, found, err := s.msgs.GetMessage(replyID); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to look up reply target")
			return
		} else if found {
			mp.ThreadRefs = client.BuildThreadRefs(replyID, m.ThreadRefs)
		} else {
			mp.ThreadRefs[0] = replyID
		}
	}

	var (
		payload blockstore.Payload
		err     error
	)
	if signerID != nil {
		payload, err = client.EncryptChannelSigned(channelKey, mp, signerID.SignKey)
	} else {
		payload, err = client.EncryptChannel(channelKey, mp)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var stamp blockstore.Stamp
	id, err := s.blocks.Put(stamp, payload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store block")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"block_id": hex.EncodeToString(id[:])})
}

// GET /api/contacts
func (s *Server) handleListContacts(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	cs := s.ks.ListContacts()
	s.mu.RUnlock()

	type contactResp struct {
		Name      string `json:"name"`
		PublicKey string `json:"public_key"`
	}
	out := make([]contactResp, len(cs))
	for i, c := range cs {
		out[i] = contactResp{
			Name:      c.Name,
			PublicKey: base64.StdEncoding.EncodeToString(c.PublicKey),
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// POST /api/contacts  {"name":"...","public_key":"<base64 Ed25519>"}
func (s *Server) handleAddContact(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		PublicKey string `json:"public_key"`
	}
	if !decode(w, r, &req) {
		return
	}
	pubBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid public_key encoding")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	c, err := s.ks.AddContact(req.Name, pubBytes)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err := s.ks.Save(s.ksPath); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save keystore")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{
		"name":       c.Name,
		"public_key": base64.StdEncoding.EncodeToString(c.PublicKey),
	})
}

// DELETE /api/contacts/{pub_key}  (pub_key is base64url no-padding)
func (s *Server) handleRemoveContact(w http.ResponseWriter, r *http.Request) {
	pubBytes, err := base64.RawURLEncoding.DecodeString(r.PathValue("pub_key"))
	if err != nil || len(pubBytes) != 32 {
		writeError(w, http.StatusBadRequest, "invalid pub_key")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.ks.RemoveContact(pubBytes) {
		writeError(w, http.StatusNotFound, "contact not found")
		return
	}
	if err := s.ks.Save(s.ksPath); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save keystore")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// PATCH /api/contacts/{pub_key}  {"name":"new name"}  (pub_key is base64url no-padding)
func (s *Server) handleRenameContact(w http.ResponseWriter, r *http.Request) {
	pubBytes, err := base64.RawURLEncoding.DecodeString(r.PathValue("pub_key"))
	if err != nil || len(pubBytes) != 32 {
		writeError(w, http.StatusBadRequest, "invalid pub_key")
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &req) {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	found, err := s.ks.RenameContact(pubBytes, req.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "contact not found")
		return
	}
	if err := s.ks.Save(s.ksPath); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save keystore")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

// splitBytes splits b into chunks of at most size bytes.
func splitBytes(b []byte, size int) [][]byte {
	var chunks [][]byte
	for len(b) > 0 {
		n := size
		if n > len(b) {
			n = len(b)
		}
		chunks = append(chunks, b[:n])
		b = b[n:]
	}
	return chunks
}
