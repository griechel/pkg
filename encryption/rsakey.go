// Copyright 2016 Palantir Technologies. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
)

type RSAPublicKey rsa.PublicKey
type RSAPrivateKey rsa.PrivateKey

func NewRSAKeyPair(keySizeBits int) (pubKey, privKey Key, err error) {
	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, keySizeBits)
	if err != nil {
		return nil, nil, err
	}
	return rsaPublicKeyFromKey(&rsaPrivKey.PublicKey), rsaPrivateKeyFromKey(rsaPrivKey), nil
}

func RSAPublicKeyFromBytes(key []byte) (Key, error) {
	var errInvalidRSAPublicKeyError = fmt.Errorf("key is not a valid PEM-encoded RSA public key")

	block, _ := pem.Decode(key)
	if block == nil {
		return nil, errInvalidRSAPublicKeyError
	}
	pkixPubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errInvalidRSAPublicKeyError
	}
	rsaPubKey, ok := pkixPubKey.(*rsa.PublicKey)
	if !ok {
		return nil, errInvalidRSAPublicKeyError
	}
	return rsaPublicKeyFromKey(rsaPubKey), nil
}

func rsaPublicKeyFromKey(rsaPubKey *rsa.PublicKey) Key {
	return (*RSAPublicKey)(rsaPubKey)
}

func RSAPrivateKeyFromBytes(key []byte) (Key, error) {
	pkcsPrivKey, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("invalid PKCS8 private key: %v", err)
	}
	rsaPrivKey, ok := pkcsPrivKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid PKCS8 private key: %v", err)
	}
	return rsaPrivateKeyFromKey(rsaPrivKey), nil
}

func rsaPrivateKeyFromKey(rsaPrivKey *rsa.PrivateKey) Key {
	return (*RSAPrivateKey)(rsaPrivKey)
}

func (r *RSAPublicKey) Bytes() []byte {
	asn1PubKey, err := x509.MarshalPKIXPublicKey((*rsa.PublicKey)(r))
	if err != nil {
		// should never occur for valid key
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: asn1PubKey,
	})
}

func (r *RSAPrivateKey) Bytes() []byte {
	pkey := struct {
		Version             int
		PrivateKeyAlgorithm []asn1.ObjectIdentifier
		PrivateKey          []byte
	}{
		Version:             0,
		PrivateKeyAlgorithm: make([]asn1.ObjectIdentifier, 1),
	}
	// https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem, see bottom
	pkey.PrivateKeyAlgorithm[0] = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	pkey.PrivateKey = x509.MarshalPKCS1PrivateKey((*rsa.PrivateKey)(r))
	bytes, err := asn1.Marshal(pkey)
	if err != nil {
		// should never occur for valid key
		panic(err)
	}
	return bytes
}
