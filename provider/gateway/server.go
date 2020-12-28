package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/libs/log"

	"github.com/ovrclk/akash/provider"
	ctypes "github.com/ovrclk/akash/x/cert/types"
)

func NewServer(
	ctx context.Context,
	log log.Logger,
	pclient provider.Client,
	cquery ctypes.QueryClient,
	address string,
	pid sdk.Address,
	certs []tls.Certificate) *http.Server {

	srv := &http.Server{
		Addr:    address,
		Handler: newRouter(log, pid, pclient),
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	srv.TLSConfig = &tls.Config{
		Certificates:       certs,
		ClientAuth:         tls.RequestClientCert,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		VerifyPeerCertificate: func(certificates [][]byte, _ [][]*x509.Certificate) error {
			if len(certificates) > 0 {
				if len(certificates) != 1 {
					return errors.Errorf("invalid certificate chain")
				}

				cert, err := x509.ParseCertificate(certificates[0])
				if err != nil {
					return errors.Wrap(err, "failed to parse certificate")
				}

				// validation
				// 1. CommonName in issuer and Subject must be the same
				if cert.Subject.CommonName != cert.Issuer.CommonName {
					return errors.Wrap(err, "invalid certificate")
				}

				var owner sdk.Address
				if owner, err = sdk.AccAddressFromBech32(cert.Subject.CommonName); err != nil {
					return errors.Wrap(err, "invalid certificate")
				}

				// 2. serial number must be in
				if cert.SerialNumber == nil {
					return errors.Wrap(err, "invalid certificate")
				}

				// 3. look up certificate on chain
				var resp *ctypes.QueryCertificatesResponse
				resp, err = cquery.Certificates(
					context.Background(),
					&ctypes.QueryCertificatesRequest{
						Filter: ctypes.CertificateFilter{
							Owner:  owner.String(),
							Serial: cert.SerialNumber.String(),
							State:  "valid",
						},
					},
				)
				if err != nil {
					return err
				}

				clientCertPool := x509.NewCertPool()

				if !clientCertPool.AppendCertsFromPEM(resp.Certificates[0].Cert) {
					return errors.Wrap(err, "invalid certificate")
				}

				opts := x509.VerifyOptions{
					Roots:                     clientCertPool,
					CurrentTime:               time.Now(),
					KeyUsages:                 []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
					MaxConstraintComparisions: 0,
				}

				if _, err = cert.Verify(opts); err != nil {
					return errors.Wrap(err, "invalid certificate")
				}
			}
			return nil
		},
	}

	return srv
}
