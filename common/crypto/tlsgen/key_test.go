/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tlsgen

import (
	"encoding/pem"
	"testing"

	"github.com/hyperledger/fabric/third_party/github.com/tjfoc/gmsm/sm2"
	tls "github.com/hyperledger/fabric/third_party/github.com/tjfoc/gmtls"
	"github.com/stretchr/testify/assert"
)

func TestCertEncoding(t *testing.T) {
	pair, err := newCertKeyPair(false, false, "", nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, pair)
	assert.NotEmpty(t, pair.PrivKeyString())
	assert.NotEmpty(t, pair.PubKeyString())
	pair2, err := CertKeyPairFromString(pair.PrivKeyString(), pair.PubKeyString())
	assert.Equal(t, pair.Key, pair2.Key)
	assert.Equal(t, pair.Cert, pair2.Cert)
}

func TestLoadCert(t *testing.T) {
	pair, err := newCertKeyPair(false, false, "", nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, pair)
	tlsCertPair, err := tls.X509KeyPair(pair.Cert, pair.Key)
	assert.NoError(t, err)
	assert.NotNil(t, tlsCertPair)
	block, _ := pem.Decode(pair.Cert)
	cert, err := sm2.ParseCertificate(block.Bytes)
	assert.NoError(t, err)
	assert.NotNil(t, cert)
}
