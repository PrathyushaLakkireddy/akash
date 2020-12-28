package utils

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/pkg/errors"

	ctypes "github.com/ovrclk/akash/x/cert/types"
)

// LoadPEMFromFrom load certificate/private key from file named as
// account name supplied in FlagFrom
// file must contain two PEM blocks, certificate followed by a private key
func LoadPEMFromFrom(homedir string, key sdk.Address, keyring keyring.Keyring) ([]byte, []byte, []byte, error) {
	sig, _, err := keyring.SignByAddress(key, key.Bytes())
	if err != nil {
		return nil, nil, nil, err
	}

	var pdata []byte

	pdata, err = ioutil.ReadFile(homedir + "/" + key.String() + ".pem")
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, nil, err
	}

	var bcrt *pem.Block
	var bkey *pem.Block

	var kdata []byte
	bcrt, kdata = pem.Decode(pdata)
	bkey, _ = pem.Decode(kdata)

	if bcrt == nil {
		return nil, nil, nil, errors.Errorf("no certificate found")
	}

	if bkey == nil {
		return nil, nil, nil, errors.Errorf("no private key found")
	}

	pdata = pdata[:len(pdata)-len(kdata)]

	var pkey []byte
	if pkey, err = x509.DecryptPEMBlock(bkey, sig); err != nil {
		return nil, nil, nil, err
	}

	var priv interface{}
	if priv, err = x509.ParsePKCS8PrivateKey(pkey); err != nil {
		return nil, nil, nil, errors.Wrapf(err, "coudn't parse private key")
	}

	eckey, valid := priv.(*ecdsa.PrivateKey)
	if !valid {
		return nil, nil, nil, fmt.Errorf("unknown key type. expected %s, desired %s",
			reflect.TypeOf(&ecdsa.PrivateKey{}), reflect.TypeOf(eckey))
	}

	var pubKey []byte
	if pubKey, err = x509.MarshalPKIXPublicKey(eckey.Public()); err != nil {
		return nil, nil, nil, err
	}

	return pdata, pem.EncodeToMemory(&pem.Block{Type: ctypes.PemBlkTypeECPrivateKey, Bytes: pkey}), pubKey, nil
}

// LoadCertificateFromFrom wraps LoadPEMFromFrom and tls.X509KeyPair
func LoadCertificateFromFrom(homedir string, key sdk.Address, keyring keyring.Keyring) (tls.Certificate, error) {
	pcrt, pkey, _, err := LoadPEMFromFrom(homedir, key, keyring)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert, err := tls.X509KeyPair(pcrt, pkey)
	if err != nil {
		return tls.Certificate{}, err
	}

	return cert, nil
}
