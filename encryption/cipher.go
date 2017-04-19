// Copyright 2016 Palantir Technologies. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package encryption

type Cipher interface {
	Encrypt(data []byte, key Key) ([]byte, error)
	Decrypt(data []byte, key Key) ([]byte, error)
}

type Key interface {
	Bytes() []byte
}
