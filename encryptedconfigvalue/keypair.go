// Copyright 2016 Palantir Technologies. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package encryptedconfigvalue

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/palantir/pkg/encryption"
)

type KeyPair struct {
	EncryptionKey KeyWithType
	DecryptionKey KeyWithType
}

type KeyWithType struct {
	Type KeyType
	Key  encryption.Key
}

type Encrypter interface {
	Encrypt(key KeyWithType, input string) (EncryptedValue, error)
}

func (kwt KeyWithType) ToSerializable() string {
	return fmt.Sprintf("%s:%s", kwt.Type, base64.StdEncoding.EncodeToString(kwt.Key.Bytes()))
}

func NewKeyWithType(input string) (KeyWithType, error) {
	parts := strings.Split(input, ":")
	if len(parts) != 2 {
		return KeyWithType{}, fmt.Errorf("key must be of the form <algorithm>:<key in base64>, was: %s", input)
	}

	keyBytes, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return KeyWithType{}, fmt.Errorf("failed to base64-decode key: %v", err)
	}

	if parts[0] == "RSA" {
		if privKey, err := RSAPrivateKeyFromBytes(keyBytes); err == nil {
			// legacy private key
			return privKey, nil
		} else if pubKey, err := RSAPublicKeyFromBytes(keyBytes); err == nil {
			// legacy public key
			return pubKey, nil
		}

		// could not parse legacy key
		return KeyWithType{}, fmt.Errorf("unable to parse legacy RSA key")
	}

	alg, err := ToKeyType(parts[0])
	if err != nil {
		return KeyWithType{}, err
	}
	return alg.Generator()(keyBytes)
}
