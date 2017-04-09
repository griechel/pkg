// Copyright 2016 Palantir Technologies. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package encryptedconfigvalue

import (
	"fmt"

	"github.com/palantir/pkg/encryption"
)

type AlgorithmType string

const (
	AES = AlgorithmType("AES")
	RSA = AlgorithmType("RSA")
)

type keyPairGenerator func() (KeyPair, error)

type algorithmTypeData struct {
	generator keyPairGenerator
	encrypter Encrypter
}

var algorithmTypeToData = map[AlgorithmType]algorithmTypeData{
	AES: {
		generator: NewAESKeyPair,
		encrypter: NewAESGCMEncrypter(),
	},
	RSA: {
		generator: NewRSAKeyPair,
		encrypter: NewRSAOAEPEncrypter(),
	},
}

func (a AlgorithmType) GenerateKeyPair() (KeyPair, error) {
	return algorithmTypeToData[a].generator()
}

func (a AlgorithmType) Encrypter() Encrypter {
	return algorithmTypeToData[a].encrypter
}

func ToAlgorithmType(val string) (AlgorithmType, error) {
	algType := AlgorithmType(val)
	if _, ok := algorithmTypeToData[algType]; !ok {
		return AlgorithmType(""), fmt.Errorf("unknown algorithm type: %q", val)
	}
	return algType, nil
}

type KeyType string

const (
	AESKey     = KeyType("AES")
	RSAPubKey  = KeyType("RSA-PUB")
	RSAPrivKey = KeyType("RSA-PRIV")
)

type keyTypeData struct {
	generator KeyGenerator
	algType   AlgorithmType
}

var keyTypeToData = map[KeyType]keyTypeData{
	AESKey: {
		generator: keyGeneratorFor(AESKey, encryption.AESKeyFromBytes),
		algType:   AES,
	},
	RSAPubKey: {
		generator: keyGeneratorFor(RSAPubKey, encryption.RSAPublicKeyFromBytes),
		algType:   RSA,
	},
	RSAPrivKey: {
		generator: keyGeneratorFor(RSAPrivKey, encryption.RSAPrivateKeyFromBytes),
		algType:   RSA,
	},
}

func (kt KeyType) Generator() KeyGenerator {
	return keyTypeToData[kt].generator
}

func (kt KeyType) AlgorithmType() AlgorithmType {
	return keyTypeToData[kt].algType
}

type KeyGenerator func([]byte) (KeyWithType, error)

func keyGeneratorFor(keyType KeyType, keyGen func([]byte) (encryption.Key, error)) KeyGenerator {
	return func(keyBytes []byte) (KeyWithType, error) {
		key, err := keyGen(keyBytes)
		if err != nil {
			return KeyWithType{}, err
		}
		return KeyWithType{
			Type: keyType,
			Key:  key,
		}, nil
	}
}

func ToKeyType(val string) (KeyType, error) {
	keyType := KeyType(val)
	if _, ok := keyTypeToData[keyType]; !ok {
		return KeyType(""), fmt.Errorf("unknown key type: %q", val)
	}
	return keyType, nil
}
