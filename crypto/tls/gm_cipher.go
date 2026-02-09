// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sm3"
	"crypto/sm4"
	"errors"
	"hash"
)

// GM (Chinese National Cryptographic Algorithm) cipher suites support

// sm4GCM implements the AEAD interface for SM4-GCM
type sm4GCM struct {
	cipher.AEAD
	nonce      [12]byte
	nonceSize  int
	explicitIV int
}

func (s *sm4GCM) explicitNonceLen() int {
	return s.explicitIV
}

// newSM4GCM creates a new SM4-GCM AEAD instance
func newSM4GCM(key, nonceMask []byte) aead {
	if len(nonceMask) != 4 {
		panic("tls: wrong nonce length for SM4-GCM")
	}

	block, err := sm4.NewCipher(key)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	ret := &sm4GCM{
		AEAD:       gcm,
		nonceSize:  12,
		explicitIV: 8,
	}

	// Copy the fixed nonce mask
	copy(ret.nonce[:4], nonceMask)

	return ret
}

// Seal encrypts and authenticates plaintext
func (s *sm4GCM) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != s.explicitIV {
		panic("tls: incorrect nonce length given to SM4-GCM")
	}

	// Construct the actual nonce: fixed part (4 bytes) || explicit part (8 bytes)
	copy(s.nonce[4:], nonce)

	return s.AEAD.Seal(dst, s.nonce[:], plaintext, additionalData)
}

// Open decrypts and authenticates ciphertext
func (s *sm4GCM) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != s.explicitIV {
		return nil, errors.New("tls: incorrect nonce length given to SM4-GCM")
	}

	// Construct the actual nonce: fixed part (4 bytes) || explicit part (8 bytes)
	copy(s.nonce[4:], nonce)

	return s.AEAD.Open(dst, s.nonce[:], ciphertext, additionalData)
}

// cipherSM4 creates the cipher function for SM4-GCM
func cipherSM4(key, iv []byte, isRead bool) interface{} {
	return newSM4GCM(key, iv)
}

// gmECDHEKA creates a key agreement for ECDHE with SM2
func gmECDHEKA(version uint16) keyAgreement {
	if version < VersionTLS12 {
		return nil
	}
	return newSM2KeyAgreement(version)
}

// prfSM3 implements the TLS 1.2 PRF with SM3
func prfSM3(result, secret, label, seed []byte) {
	labelAndSeed := make([]byte, len(label)+len(seed))
	copy(labelAndSeed, label)
	copy(labelAndSeed[len(label):], seed)

	pHashSM3(result, secret, labelAndSeed)
}

// pHashSM3 implements the P_hash function from TLS 1.2 with SM3
func pHashSM3(result, secret, seed []byte) {
	h := sm3.New()
	h.Write(secret)
	h.Write(seed)
	a := h.Sum(nil)

	j := 0
	for j < len(result) {
		h.Reset()
		h.Write(secret)
		h.Write(a)
		h.Write(seed)
		b := h.Sum(nil)

		todo := len(b)
		if j+todo > len(result) {
			todo = len(result) - j
		}
		copy(result[j:j+todo], b)
		j += todo

		h.Reset()
		h.Write(secret)
		h.Write(a)
		a = h.Sum(nil)
	}
}

// newFinishedHashSM3 creates a new finished hash for SM3-based cipher suites
func newFinishedHashSM3(version uint16) finishedHash {
	return finishedHash{
		client:  sm3.New(),
		server:  sm3.New(),
		version: version,
		prf:     prfSM3,
	}
}

// gmCipherSuiteByID returns a GM cipher suite by its ID
func gmCipherSuiteByID(id uint16) *cipherSuite {
	switch id {
	case TLS_SM2_WITH_SM4_GCM_SM3:
		return &cipherSuite{
			id:     TLS_SM2_WITH_SM4_GCM_SM3,
			keyLen: 16,
			macLen: 0,
			ivLen:  4,
			ka:     gmECDHEKA,
			flags:  suiteECDHE | suiteTLS12 | suiteSHA384,
			cipher: cipherSM4,
			mac:    nil,
			aead:   newSM4GCM,
		}
	default:
		return nil
	}
}

// isGMCipherSuite checks if a cipher suite ID is a GM suite
func isGMCipherSuite(id uint16) bool {
	switch id {
	case TLS_SM2_WITH_SM4_GCM_SM3, TLS_SM2_WITH_SM4_CBC_SM3:
		return true
	default:
		return false
	}
}

// aeadSM4GCM creates an SM4-GCM AEAD for TLS 1.2
func aeadSM4GCM(key, noncePrefix []byte) aead {
	return newSM4GCM(key, noncePrefix)
}

// aeadSM4GCMTLS13 creates an SM4-GCM AEAD for TLS 1.3
// TLS 1.3 uses a different nonce construction with XOR
func aeadSM4GCMTLS13(key, nonceMask []byte) aead {
	if len(nonceMask) != aeadNonceLength {
		panic("tls: internal error: wrong nonce length for SM4-GCM TLS 1.3")
	}

	block, err := sm4.NewCipher(key)
	if err != nil {
		panic(err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	ret := &xorNonceAEAD{aead: aead}
	copy(ret.nonceMask[:], nonceMask)
	return ret
}

// macSM3 returns an SM3-based MAC for TLS 1.2
func macSM3(key []byte) hash.Hash {
	return hmac.New(sm3.New, key)
}

// Placeholder for future GM CBC mode support
func cipherSM4CBC(key, iv []byte, isRead bool) interface{} {
	panic("tls: SM4-CBC not yet implemented")
}

// gmHashForSuite returns the hash function for a GM cipher suite
func gmHashForSuite(suite *cipherSuite) func() hash.Hash {
	return sm3.New
}

// Verify that sm4GCM implements the aead interface
var _ aead = (*sm4GCM)(nil)
