// Copyright 2016 Palantir Technologies. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package encryptedconfigvalue

import (
	"encoding/base64"
	"fmt"

	"github.com/palantir/pkg/encryption"
)

type legacyEncryptedValue struct {
	encryptedBytes []byte
}

func (ev *legacyEncryptedValue) Decrypt(key KeyWithType) (string, error) {
	ciphertext := ev.encryptedBytes
	switch key.Key.(type) {
	default:
		return "", fmt.Errorf("key type %T not supported", key.Key)
	case *encryption.AESKey:
		const (
			legacyAESNonceBytes = 32
			legacyAESTagBytes   = 16
		)
		aesGCMEV := &aesGCMEncryptedValue{
			encrypted: ciphertext[legacyAESNonceBytes : len(ciphertext)-legacyAESTagBytes],
			nonce:     ciphertext[:legacyAESNonceBytes],
			tag:       ciphertext[len(ciphertext)-legacyAESTagBytes:],
		}
		return aesGCMEV.Decrypt(key)
	case *encryption.RSAPrivateKey:
		rsaOAEPEV := &rsaOAEPEncryptedValue{
			encrypted:   ciphertext,
			oaepHashAlg: encryption.SHA256,
			mdf1HashAlg: encryption.SHA1,
		}
		return rsaOAEPEV.Decrypt(key)
	}
}

func (ev *legacyEncryptedValue) ToSerializable() (string, error) {
	return fmt.Sprintf(encPrefix + base64.StdEncoding.EncodeToString(ev.encryptedBytes)), nil
}
