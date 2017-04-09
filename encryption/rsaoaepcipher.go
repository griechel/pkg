// Copyright 2016 Palantir Technologies. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
)

type HashAlgorithm string

const (
	SHA1   = HashAlgorithm("SHA-1")
	SHA256 = HashAlgorithm("SHA-256")
)

func (a HashAlgorithm) Hash() hash.Hash {
	switch a {
	case "SHA-1":
		return sha1.New()
	case "SHA-256":
		return sha256.New()
	default:
		return nil
	}
}

type RSAOAEPCipher struct {
	oaepHashAlg HashAlgorithm
	mdf1HashAlg HashAlgorithm
}

func (r *RSAOAEPCipher) OAEPHashAlg() HashAlgorithm {
	return r.oaepHashAlg
}

func (r *RSAOAEPCipher) MDF1HashAlg() HashAlgorithm {
	return r.mdf1HashAlg
}

func NewRSAOAEPCipher() Cipher {
	return &RSAOAEPCipher{
		oaepHashAlg: SHA256,
		mdf1HashAlg: SHA256,
	}
}

func RSAOAEPCipherWithAlgorithms(oaepHashAlg, mdf1HashAlg HashAlgorithm) *RSAOAEPCipher {
	return &RSAOAEPCipher{
		oaepHashAlg: oaepHashAlg,
		mdf1HashAlg: mdf1HashAlg,
	}
}

func (r *RSAOAEPCipher) Encrypt(data []byte, key Key) ([]byte, error) {
	pubKey, ok := key.(*RSAPublicKey)
	if !ok {
		return nil, fmt.Errorf("key must be of *RSAPublicKey, but was %T", key)
	}
	encrypted, err := encryptOAEP(r.oaepHashAlg.Hash(), r.mdf1HashAlg.Hash(), rand.Reader, (*rsa.PublicKey)(pubKey), data, []byte{})
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

func (r *RSAOAEPCipher) Decrypt(data []byte, key Key) ([]byte, error) {
	privKey, ok := key.(*RSAPrivateKey)
	if !ok {
		return nil, fmt.Errorf("key must be of type *RSAPrivateKey, was %T", key)
	}
	decrypted, err := decryptOAEP(r.oaepHashAlg.Hash(), r.mdf1HashAlg.Hash(), rand.Reader, (*rsa.PrivateKey)(privKey), data, []byte{})
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}
