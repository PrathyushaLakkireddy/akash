package types

import (
	"bytes"
	"encoding/json"

	"github.com/cosmos/cosmos-sdk/codec"
)

type GenesisCertificates []GenesisCertificate

func (obj GenesisCertificates) Contains(cert GenesisCertificate) bool {
	for _, c := range obj {
		if c.ID.Equals(cert.ID) {
			return true
		}

		// fixme is bytes.Equal right way to do it?
		if bytes.Equal(c.Certificate.Cert, cert.Certificate.Cert) {
			return true
		}
	}

	return false
}

func (m GenesisCertificate) Validate() error {
	if _, err := ToCertID(m.ID); err != nil {
		return err
	}
	if err := m.Certificate.Validate(); err != nil {
		return err
	}

	return nil
}

func (m *GenesisState) Validate() error {
	for _, cert := range m.Certificates {
		if err := cert.Certificate.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// GetGenesisStateFromAppState returns x/cert GenesisState given raw application
// genesis state.
func GetGenesisStateFromAppState(cdc codec.JSONMarshaler, appState map[string]json.RawMessage) *GenesisState {
	var genesisState GenesisState

	if appState[ModuleName] != nil {
		cdc.MustUnmarshalJSON(appState[ModuleName], &genesisState)
	}

	return &genesisState
}
