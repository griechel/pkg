// Copyright 2016 Palantir Technologies. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

type AESGCMCipher struct {
	nonceSizeBytes int
	tagSizeBytes   int
}

const (
	aesGCMDefaultNonceSizeBytes = 12
	aesGCMDefaultTagSizeBytes   = 16
)

func NewAESGCMCipher() *AESGCMCipher {
	return &AESGCMCipher{
		nonceSizeBytes: aesGCMDefaultNonceSizeBytes,
		tagSizeBytes:   aesGCMDefaultTagSizeBytes,
	}
}

func AESGCMCipherWithNonceAndTagSize(nonceSizeBytes, tagSizeBytes int) *AESGCMCipher {
	return &AESGCMCipher{
		nonceSizeBytes: nonceSizeBytes,
		tagSizeBytes:   tagSizeBytes,
	}
}

func (a *AESGCMCipher) Encrypt(data []byte, key Key) ([]byte, error) {
	aesKey, ok := key.(*AESKey)
	if !ok {
		return nil, fmt.Errorf("key must be of *AESKey, but was %T", key)
	}

	gcm, err := newBlockCipher(aesKey, a.nonceSizeBytes)
	if err != nil {
		return nil, err
	}

	// generate random nonce/IV
	nonce, err := randomBytes(gcm.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	encrypted := gcm.Seal(nil, nonce, data, nil)

	return append(nonce, encrypted...), nil
}

func (a *AESGCMCipher) Parts(encryptedData []byte) (nonce []byte, encrypted []byte, tags []byte) {
	return encryptedData[:a.nonceSizeBytes],
		encryptedData[a.nonceSizeBytes : len(encryptedData)-a.tagSizeBytes],
		encryptedData[len(encryptedData)-a.tagSizeBytes:]
}

func (a *AESGCMCipher) Decrypt(data []byte, key Key) ([]byte, error) {
	aesKey, ok := key.(*AESKey)
	if !ok {
		return nil, fmt.Errorf("key must be of type *AESKey, was %T", key)
	}

	gcm, err := newBlockCipher(aesKey, a.nonceSizeBytes)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, data[:a.nonceSizeBytes], data[a.nonceSizeBytes:], nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt value: %v", err)
	}
	return plain, nil
}

func newBlockCipher(key *AESKey, nonceSizeBytes int) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key.key)
	if err != nil {
		return nil, fmt.Errorf("failed to construct AES cipher: %v", err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, nonceSizeBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to construct block cipher: %v", err)
	}
	return gcm, nil
}
