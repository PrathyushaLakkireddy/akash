package types

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/pkg/errors"
)

func (m *CertificateID) String() string {
	return fmt.Sprintf("%s/%s", m.Owner, m.Serial)
}

func (m *CertificateID) Equals(val CertificateID) bool {
	return (m.Owner == val.Owner) && (m.Serial == m.Serial)
}

func (m Certificate) Validate() error {
	if val, exists := Certificate_State_name[int32(m.State)]; !exists || val == "invalid" {
		return ErrInvalidState
	}

	blk, _ := pem.Decode(m.Cert)
	if blk == nil {
		return ErrInvalidCertificateValue
	}

	if blk.Type != PemBlkTypeCertificate {
		return errors.Wrap(ErrInvalidCertificateValue, "invalid pem block type")
	}

	_, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return err
	}

	if blk, _ = pem.Decode(m.Pubkey); blk == nil {
		return ErrInvalidPubkeyValue
	}

	if blk.Type != PemBlkTypeECPublicKey {
		return errors.Wrap(ErrInvalidPubkeyValue, "invalid pem block type")
	}

	return nil
}
