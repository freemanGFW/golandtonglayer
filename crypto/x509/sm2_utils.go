// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"crypto/elliptic"
	"crypto/sm2"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// parseSM2PrivateKey parses an ASN.1 SM2 Private Key Structure.
// The OID for the named curve may be provided from another source (such as
// the PKCS8 container) - if it is provided then use this instead of the OID
// that may exist in the private key structure.
func parseSM2PrivateKey(namedCurveOID *asn1.ObjectIdentifier, der []byte) (key *sm2.PrivateKey, err error) {
	var privKey ecPrivateKey
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		if _, err := asn1.Unmarshal(der, &pkcs8{}); err == nil {
			return nil, errors.New("x509: failed to parse private key (use ParsePKCS8PrivateKey instead for this key format)")
		}
		return nil, errors.New("x509: failed to parse SM2 private key: " + err.Error())
	}
	if privKey.Version != ecPrivKeyVersion {
		return nil, fmt.Errorf("x509: unknown SM2 private key version %d", privKey.Version)
	}

	var curve elliptic.Curve
	if namedCurveOID != nil {
		curve = namedCurveFromOID(*namedCurveOID)
	} else {
		curve = namedCurveFromOID(privKey.NamedCurveOID)
	}
	if curve == nil {
		return nil, errors.New("x509: unknown elliptic curve for SM2")
	}

	// 验证是否为SM2曲线
	if curve != sm2.P256Sm2() {
		return nil, errors.New("x509: not an SM2 curve")
	}

	k := new(big.Int).SetBytes(privKey.PrivateKey)
	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, errors.New("x509: invalid SM2 private key value")
	}

	priv := new(sm2.PrivateKey)
	priv.Curve = curve
	priv.D = k

	privateKey := make([]byte, (curveOrder.BitLen()+7)/8)

	// Some private keys have leading zero padding. This is invalid
	// according to [SEC1], but this code will ignore it.
	for len(privKey.PrivateKey) > len(privateKey) {
		if privKey.PrivateKey[0] != 0 {
			return nil, errors.New("x509: invalid private key length")
		}
		privKey.PrivateKey = privKey.PrivateKey[1:]
	}

	// Some private keys remove all leading zeros, this is also invalid
	// according to [SEC1] but since OpenSSL used to do this, we ignore
	// this too.
	copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(privateKey)
	priv.PublicKey.Curve = curve

	return priv, nil
}

// marshalSM2PrivateKeyWithOID marshals an SM2 private key into ASN.1, DER format and
// sets the curve ID to the given OID, or omits it if OID is nil.
func marshalSM2PrivateKeyWithOID(key *sm2.PrivateKey, oid asn1.ObjectIdentifier) ([]byte, error) {
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, errors.New("x509: invalid SM2 public key")
	}
	privateKey := make([]byte, (key.Curve.Params().N.BitLen()+7)/8)
	return asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    key.D.FillBytes(privateKey),
		NamedCurveOID: oid,
		PublicKey:     asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)},
	})
}

// ParseSM2PrivateKey parses an SM2 private key in SEC 1, ASN.1 DER form.
//
// This kind of key is commonly encoded in PEM blocks of type "EC PRIVATE KEY"
// or "SM2 PRIVATE KEY".
func ParseSM2PrivateKey(der []byte) (*sm2.PrivateKey, error) {
	return parseSM2PrivateKey(nil, der)
}

// MarshalSM2PrivateKey converts an SM2 private key to SEC 1, ASN.1 DER form.
//
// This kind of key is commonly encoded in PEM blocks of type "EC PRIVATE KEY"
// or "SM2 PRIVATE KEY".
// For a more flexible key format which is not EC specific, use
// MarshalPKCS8PrivateKey.
func MarshalSM2PrivateKey(key *sm2.PrivateKey) ([]byte, error) {
	oid := oidNamedCurveP256SM2
	return marshalSM2PrivateKeyWithOID(key, oid)
}
