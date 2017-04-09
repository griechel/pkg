// Copyright 2016 Palantir Technologies. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package encryptedconfigvalue

import (
	"github.com/palantir/pkg/encryption"
)

func NewAESKey(keySizeBits int) (KeyWithType, error) {
	key, err := encryption.NewAESKey(keySizeBits)
	if err != nil {
		return KeyWithType{}, err
	}
	return KeyWithType{
		Type: AESKey,
		Key:  key,
	}, nil
}

func AESKeyFromBytes(key []byte) (KeyWithType, error) {
	aesKey, err := encryption.AESKeyFromBytes(key)
	if err != nil {
		return KeyWithType{}, err
	}
	return KeyWithType{
		Type: AESKey,
		Key:  aesKey,
	}, nil
}

const defaultAESKeySizeBits = 256

func NewAESKeyPair() (KeyPair, error) {
	aesKey, err := NewAESKey(defaultAESKeySizeBits)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{
		EncryptionKey: aesKey,
		DecryptionKey: aesKey,
	}, nil
}
