// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/elliptic"
	"crypto/sm2"
	"crypto/sm3"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
)

// sm2KeyAgreement implements the TLS key agreement protocol using SM2 ECDHE.
// This is used for GM cipher suites that use SM2 for both key agreement and signing.
type sm2KeyAgreement struct {
	version uint16

	// Server side: generated in generateServerKeyExchange
	privateKey *sm2.PrivateKey

	// Client side: generated in processServerKeyExchange
	// and returned in generateClientKeyExchange
	ckx             *clientKeyExchangeMsg
	preMasterSecret []byte
}

// generateServerKeyExchange generates the ServerKeyExchange message for SM2 ECDHE.
// This includes the server's ephemeral public key and signature.
func (ka *sm2KeyAgreement) generateServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	// Check if client supports SM2 curve
	var supportsSM2 bool
	for _, c := range clientHello.supportedCurves {
		if c == CurveSM2 {
			supportsSM2 = true
			break
		}
	}

	if !supportsSM2 {
		return nil, errors.New("tls: client does not support SM2 curve")
	}

	// Generate ephemeral SM2 key pair
	privateKey, err := sm2.GenerateKey(config.rand())
	if err != nil {
		return nil, err
	}
	ka.privateKey = privateKey

	// Encode public key: 0x04 || X || Y (uncompressed point)
	pubKey := privateKey.Public().(*sm2.PublicKey)
	publicKeyBytes := ellipticMarshal(pubKey.Curve, pubKey.X, pubKey.Y)

	// Build ServerKeyExchange parameters
	// Curve Type (1 byte) | Curve ID (2 bytes) | Public Key Length (1 byte) | Public Key
	serverECDHEParams := make([]byte, 1+2+1+len(publicKeyBytes))
	serverECDHEParams[0] = 3 // named curve
	serverECDHEParams[1] = byte(CurveSM2 >> 8)
	serverECDHEParams[2] = byte(CurveSM2)
	serverECDHEParams[3] = byte(len(publicKeyBytes))
	copy(serverECDHEParams[4:], publicKeyBytes)

	// Get signing key from certificate
	priv, ok := cert.PrivateKey.(*sm2.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("tls: certificate private key is not SM2, got %T", cert.PrivateKey)
	}

	// Sign the parameters
	var signatureAlgorithm SignatureScheme
	if ka.version >= VersionTLS12 {
		// For SM2, we use SM2WithSM3 signature algorithm
		signatureAlgorithm = SM2WithSM3

		// Verify client supports SM2WithSM3
		var supportsSignature bool
		for _, sigAlg := range clientHello.supportedSignatureAlgorithms {
			if sigAlg == SM2WithSM3 {
				supportsSignature = true
				break
			}
		}
		if !supportsSignature {
			return nil, errors.New("tls: client does not support SM2WithSM3 signature algorithm")
		}
	}

	// Prepare data to be signed: client_random + server_random + server_params
	signed := make([]byte, 0, len(clientHello.random)+len(hello.random)+len(serverECDHEParams))
	signed = append(signed, clientHello.random...)
	signed = append(signed, hello.random...)
	signed = append(signed, serverECDHEParams...)

	// Hash the data with SM3
	hash := sm3.New()
	hash.Write(signed)
	digest := hash.Sum(nil)

	// Sign with SM2
	sig, err := priv.Sign(config.rand(), digest, crypto.Hash(0))
	if err != nil {
		return nil, errors.New("tls: failed to sign ECDHE parameters: " + err.Error())
	}

	// Build ServerKeyExchange message
	skx := new(serverKeyExchangeMsg)
	sigAndHashLen := 0
	if ka.version >= VersionTLS12 {
		sigAndHashLen = 2 // signature algorithm
	}
	skx.key = make([]byte, len(serverECDHEParams)+sigAndHashLen+2+len(sig))
	copy(skx.key, serverECDHEParams)
	k := skx.key[len(serverECDHEParams):]

	if ka.version >= VersionTLS12 {
		k[0] = byte(signatureAlgorithm >> 8)
		k[1] = byte(signatureAlgorithm)
		k = k[2:]
	}
	k[0] = byte(len(sig) >> 8)
	k[1] = byte(len(sig))
	copy(k[2:], sig)

	return skx, nil
}

// processClientKeyExchange processes the ClientKeyExchange message and derives
// the pre-master secret using SM2 ECDH.
func (ka *sm2KeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	if len(ckx.ciphertext) == 0 || int(ckx.ciphertext[0]) != len(ckx.ciphertext)-1 {
		return nil, errClientKeyExchange
	}

	// Parse client's public key
	publicKeyBytes := ckx.ciphertext[1:]
	x, y := ellipticUnmarshal(sm2.P256Sm2(), publicKeyBytes)
	if x == nil {
		return nil, errClientKeyExchange
	}

	clientPublicKey := &sm2.PublicKey{
		Curve: sm2.P256Sm2(),
		X:     x,
		Y:     y,
	}

	// Perform ECDH to get pre-master secret
	preMasterSecret := sm2ECDH(ka.privateKey, clientPublicKey)
	if preMasterSecret == nil {
		return nil, errClientKeyExchange
	}

	return preMasterSecret, nil
}

// processServerKeyExchange processes the ServerKeyExchange message and verifies
// the server's signature.
func (ka *sm2KeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	if len(skx.key) < 4 {
		return errServerKeyExchange
	}

	if skx.key[0] != 3 { // named curve
		return errors.New("tls: server selected unsupported curve type")
	}

	curveID := CurveID(skx.key[1])<<8 | CurveID(skx.key[2])
	if curveID != CurveSM2 {
		return errors.New("tls: server selected non-SM2 curve")
	}

	publicLen := int(skx.key[3])
	if publicLen+4 > len(skx.key) {
		return errServerKeyExchange
	}

	serverECDHEParams := skx.key[:4+publicLen]
	publicKeyBytes := serverECDHEParams[4:]

	sig := skx.key[4+publicLen:]

	// Parse signature algorithm (TLS 1.2+)
	var signatureAlgorithm SignatureScheme
	if ka.version >= VersionTLS12 {
		if len(sig) < 2 {
			return errServerKeyExchange
		}
		signatureAlgorithm = SignatureScheme(sig[0])<<8 | SignatureScheme(sig[1])
		sig = sig[2:]

		if signatureAlgorithm != SM2WithSM3 {
			return errors.New("tls: server used non-SM2 signature algorithm")
		}
	}

	if len(sig) < 2 {
		return errServerKeyExchange
	}
	sigLen := int(sig[0])<<8 | int(sig[1])
	if sigLen+2 != len(sig) {
		return errServerKeyExchange
	}
	sig = sig[2:]

	// Parse server's public key
	x, y := ellipticUnmarshal(sm2.P256Sm2(), publicKeyBytes)
	if x == nil {
		return errServerKeyExchange
	}

	serverPublicKey := &sm2.PublicKey{
		Curve: sm2.P256Sm2(),
		X:     x,
		Y:     y,
	}

	// Prepare signed data
	signed := make([]byte, 0, len(clientHello.random)+len(serverHello.random)+len(serverECDHEParams))
	signed = append(signed, clientHello.random...)
	signed = append(signed, serverHello.random...)
	signed = append(signed, serverECDHEParams...)

	// Hash with SM3
	hash := sm3.New()
	hash.Write(signed)
	digest := hash.Sum(nil)

	// Get server's certificate public key for verification
	certPublicKey, ok := cert.PublicKey.(*sm2.PublicKey)
	if !ok {
		return fmt.Errorf("tls: server certificate contains incorrect key type, expected SM2, got %T", cert.PublicKey)
	}

	// Verify signature
	if !certPublicKey.Verify(digest, sig) {
		return errors.New("tls: SM2 signature verification failed")
	}

	// Store server's ephemeral public key for later use
	ka.privateKey = &sm2.PrivateKey{
		PublicKey: *serverPublicKey,
	}

	return nil
}

// generateClientKeyExchange generates the ClientKeyExchange message and derives
// the pre-master secret.
func (ka *sm2KeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	if ka.privateKey == nil || ka.privateKey.X == nil {
		return nil, nil, errors.New("tls: missing server key exchange")
	}

	// Get server's public key from processServerKeyExchange
	serverPublicKey := &ka.privateKey.PublicKey

	// Generate client's ephemeral key pair
	clientPrivateKey, err := sm2.GenerateKey(config.rand())
	if err != nil {
		return nil, nil, err
	}

	// Perform ECDH to get pre-master secret
	preMasterSecret := sm2ECDH(clientPrivateKey, serverPublicKey)
	if preMasterSecret == nil {
		return nil, nil, errors.New("tls: SM2 ECDH failed")
	}

	// Encode client's public key
	clientPublicKey := clientPrivateKey.Public().(*sm2.PublicKey)
	publicKeyBytes := ellipticMarshal(clientPublicKey.Curve, clientPublicKey.X, clientPublicKey.Y)

	// Build ClientKeyExchange message
	ckx := new(clientKeyExchangeMsg)
	ckx.ciphertext = make([]byte, 1+len(publicKeyBytes))
	ckx.ciphertext[0] = byte(len(publicKeyBytes))
	copy(ckx.ciphertext[1:], publicKeyBytes)

	return preMasterSecret, ckx, nil
}

// Helper function to marshal elliptic curve point
func ellipticMarshal(curve elliptic.Curve, x, y *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) / 8
	ret := make([]byte, 1+2*byteLen)
	ret[0] = 4 // uncompressed point

	x.FillBytes(ret[1 : 1+byteLen])
	y.FillBytes(ret[1+byteLen : 1+2*byteLen])

	return ret
}

// Helper function to unmarshal elliptic curve point
func ellipticUnmarshal(curve elliptic.Curve, data []byte) (x, y *big.Int) {
	byteLen := (curve.Params().BitSize + 7) / 8
	if len(data) != 1+2*byteLen {
		return nil, nil
	}
	if data[0] != 4 { // uncompressed form
		return nil, nil
	}

	x = new(big.Int).SetBytes(data[1 : 1+byteLen])
	y = new(big.Int).SetBytes(data[1+byteLen : 1+2*byteLen])

	if !curve.IsOnCurve(x, y) {
		return nil, nil
	}

	return x, y
}

// newSM2KeyAgreement creates a new SM2 key agreement instance
func newSM2KeyAgreement(version uint16) keyAgreement {
	return &sm2KeyAgreement{
		version: version,
	}
}

// sm2ECDH performs Elliptic Curve Diffie-Hellman key exchange using SM2.
// It multiplies the peer's public key by the local private key to derive
// a shared secret.
func sm2ECDH(priv *sm2.PrivateKey, pub *sm2.PublicKey) []byte {
	if priv == nil || pub == nil {
		return nil
	}

	curve := sm2.P256Sm2()

	// Perform scalar multiplication: shared_point = priv.D * pub.(X, Y)
	x, _ := curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	if x == nil {
		return nil
	}

	// The shared secret is the x-coordinate of the shared point
	// Pad to the appropriate byte length
	byteLen := (curve.Params().BitSize + 7) / 8
	secret := make([]byte, byteLen)
	x.FillBytes(secret)

	return secret
}
