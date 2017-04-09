// Copyright 2016 Palantir Technologies. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package encryptedconfigvalue

import (
	"github.com/palantir/pkg/encryption"
)

func NewRSAKeys(keySizeBits int) (pubKey KeyWithType, privKey KeyWithType, err error) {
	pub, priv, err := encryption.NewRSAKeyPair(keySizeBits)
	if err != nil {
		return KeyWithType{}, KeyWithType{}, err
	}
	return KeyWithType{
			Type: RSAPubKey,
			Key:  pub,
		}, KeyWithType{
			Type: RSAPrivKey,
			Key:  priv,
		}, nil
}

func RSAPublicKeyFromBytes(key []byte) (KeyWithType, error) {
	rsaPubKey, err := encryption.RSAPublicKeyFromBytes(key)
	if err != nil {
		return KeyWithType{}, err
	}
	return KeyWithType{
		Type: RSAPubKey,
		Key:  rsaPubKey,
	}, nil
}

func RSAPrivateKeyFromBytes(key []byte) (KeyWithType, error) {
	rsaPrivKey, err := encryption.RSAPrivateKeyFromBytes(key)
	if err != nil {
		return KeyWithType{}, err
	}
	return KeyWithType{
		Type: RSAPrivKey,
		Key:  rsaPrivKey,
	}, nil
}

const defaultRSAKeySizeBits = 2048

func NewRSAKeyPair() (KeyPair, error) {
	pubKey, privKey, err := NewRSAKeys(defaultRSAKeySizeBits)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{
		EncryptionKey: pubKey,
		DecryptionKey: privKey,
	}, nil
}
