// Copyright 2016 Palantir Technologies. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package encryptedconfigvalue

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/palantir/pkg/encryption"
)

type rsaOAEPEncrypter encryption.RSAOAEPCipher

func NewRSAOAEPEncrypter() Encrypter {
	return (*rsaOAEPEncrypter)(encryption.RSAOAEPCipherWithAlgorithms(encryption.SHA256, encryption.SHA256))
}

func (r *rsaOAEPEncrypter) Encrypt(key KeyWithType, input string) (EncryptedValue, error) {
	rsaOAEPCipher := (*encryption.RSAOAEPCipher)(r)
	encrypted, err := rsaOAEPCipher.Encrypt([]byte(input), key.Key)
	if err != nil {
		return nil, err
	}
	return &rsaOAEPEncryptedValue{
		encrypted:   encrypted,
		oaepHashAlg: rsaOAEPCipher.OAEPHashAlg(),
		mdf1HashAlg: rsaOAEPCipher.MDF1HashAlg(),
	}, nil
}

const oaepMode = "OAEP"

type rsaOAEPEncryptedValue struct {
	encrypted   []byte
	oaepHashAlg encryption.HashAlgorithm
	mdf1HashAlg encryption.HashAlgorithm
}

type rsaOAEPEncryptedValueJSON struct {
	Type        string `json:"type"`
	Mode        string `json:"mode"`
	Ciphertext  string `json:"ciphertext"`
	OAEPHashAlg string `json:"oaep-alg"`
	MDF1HashAlg string `json:"mdf1-alg"`
}

func (ev rsaOAEPEncryptedValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(rsaOAEPEncryptedValueJSON{
		Type:        string(RSA),
		Mode:        oaepMode,
		Ciphertext:  base64.StdEncoding.EncodeToString(ev.encrypted),
		OAEPHashAlg: string(ev.oaepHashAlg),
		MDF1HashAlg: string(ev.mdf1HashAlg),
	})
}

func (ev *rsaOAEPEncryptedValue) UnmarshalJSON(data []byte) error {
	var evJSON rsaOAEPEncryptedValueJSON
	if err := json.Unmarshal(data, &evJSON); err != nil {
		return err
	}
	if evJSON.Mode != oaepMode {
		return fmt.Errorf("unsupported mode: only %q mode is supported for RSA, but was %q", oaepMode, evJSON.Mode)
	}

	encrypted, err := base64.StdEncoding.DecodeString(evJSON.Ciphertext)
	if err != nil {
		return err
	}
	oaepHashAlg := encryption.HashAlgorithm(evJSON.OAEPHashAlg)
	if oaepHashAlg.Hash() == nil {
		return fmt.Errorf("unrecognized hash algorithm %q specified as OAEP hash algorithm", evJSON.OAEPHashAlg)
	}
	mdf1HashAlg := encryption.HashAlgorithm(evJSON.MDF1HashAlg)
	if mdf1HashAlg.Hash() == nil {
		return fmt.Errorf("unrecognized hash algorithm %q specified as MDF1 hash algorithm", evJSON.MDF1HashAlg)
	}

	*ev = rsaOAEPEncryptedValue{
		encrypted:   encrypted,
		oaepHashAlg: oaepHashAlg,
		mdf1HashAlg: mdf1HashAlg,
	}
	return nil
}

func (ev *rsaOAEPEncryptedValue) Decrypt(key KeyWithType) (string, error) {
	cipher := encryption.RSAOAEPCipherWithAlgorithms(ev.oaepHashAlg, ev.mdf1HashAlg)
	decrypted, err := cipher.Decrypt(ev.encrypted, key.Key)
	return string(decrypted), err
}

func (ev *rsaOAEPEncryptedValue) ToSerializable() (string, error) {
	return encryptedValToSerializable(ev)
}
