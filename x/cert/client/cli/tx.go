package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/server"
	"github.com/cosmos/cosmos-sdk/x/genutil"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/ovrclk/akash/x/cert/types"
	cutils "github.com/ovrclk/akash/x/cert/utils"
)

const (
	flagNbf = "nbf"
	flagNaf = "naf"
)

var AuthVersionOID = asn1.ObjectIdentifier{2, 23, 133, 2, 6}

func GetTxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        types.ModuleName,
		Short:                      "Certificates transaction subcommands",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	cmd.AddCommand(
		cmdCreate(),
		cmdRevoke(),
	)

	return cmd
}

func cmdCreate() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "create/update api certificates",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	cmd.AddCommand(
		cmdCreateClient(),
		cmdCreateServer(),
	)

	return cmd
}

func cmdRevoke() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "revoke api certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			cctx, err := client.ReadTxCommandFlags(client.GetClientContextFromCmd(cmd), cmd.Flags())
			if err != nil {
				return err
			}

			cpem, _, _, err := cutils.LoadPEMFromFrom(cctx.HomeDir, cctx.FromAddress, cctx.Keyring)
			if err != nil {
				return err
			}

			cert, err := x509.ParseCertificate(cpem)
			if err != nil {
				return err
			}

			return doRevoke(cctx, cmd.Flags(), cert)
		},
	}

	return cmd
}

func cmdCreateClient() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "client",
		Short: "create client api certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			return doCreateCmd(cmd, false, []string{})
		},
	}

	setCreateFlags(cmd)

	return cmd
}

func cmdCreateServer() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "create server api certificate",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return doCreateCmd(cmd, true, args)
		},
	}

	setCreateFlags(cmd)

	return cmd
}

func doCreateCmd(cmd *cobra.Command, isServer bool, domains []string) error {
	toGenesis, err := cmd.Flags().GetBool("to_genesis")
	if err != nil {
		return err
	}

	cctx, err := client.ReadTxCommandFlags(client.GetClientContextFromCmd(cmd), cmd.Flags())
	if err != nil {
		return err
	}

	fromAddress := cctx.GetFromAddress()

	pemFile := cctx.HomeDir + "/" + fromAddress.String() + ".pem"

	if _, err = os.Stat(pemFile); os.IsNotExist(err) {
		_ = cctx.PrintString(fmt.Sprintf("no certificate found for address %s. generating new...\n", fromAddress))

		var msg *types.MsgCreateCertificate

		msg, err = createAuthPem(cmd, isServer, domains)
		if err != nil {
			return err
		}

		if !toGenesis {
			return tx.GenerateOrBroadcastTxCLI(cctx, cmd.Flags(), msg)
		}

		return addCertToGenesis(cmd, types.GenesisCertificate{
			ID: msg.ID,
			Certificate: types.Certificate{
				State:  types.CertificateValid,
				Cert:   msg.Cert,
				Pubkey: msg.Pubkey,
			},
		})
	} else {
		// todo handle user prompt
		cert := types.Certificate{
			State: types.CertificateValid,
		}

		cert.Cert, _, cert.Pubkey, err = cutils.LoadPEMFromFrom(cctx.HomeDir, cctx.FromAddress, cctx.Keyring)
		if err != nil {
			return err
		}
	}

	return nil
}

func setCreateFlags(cmd *cobra.Command) {
	flags.AddTxFlagsToCmd(cmd)
	if err := cmd.MarkFlagRequired(flags.FlagFrom); err != nil {
		panic(err.Error())
	}

	cmd.Flags().String(flagNbf, "", "certificate is not valid before this date. default current timestamp. RFC3339")
	cmd.Flags().String(flagNaf, "", "certificate is not valid after this date. default 365d. days or RFC3339")

	// fixme shall we use gentx instead? 🤔
	cmd.Flags().Bool("to_genesis", false, "export certificate to genesis")
}

func addCertToGenesis(cmd *cobra.Command, cert types.GenesisCertificate) error {
	cctx, err := client.ReadTxCommandFlags(client.GetClientContextFromCmd(cmd), cmd.Flags())
	if err != nil {
		return err
	}

	cdc := cctx.JSONMarshaler.(codec.Marshaler)

	serverCtx := server.GetServerContextFromCmd(cmd)
	config := serverCtx.Config

	config.SetRoot(cctx.HomeDir)

	if err := cert.Validate(); err != nil {
		return errors.Errorf("failed to validate new genesis certificate: %v", err)
	}

	genFile := config.GenesisFile()
	appState, genDoc, err := genutiltypes.GenesisStateFromGenFile(genFile)
	if err != nil {
		return errors.Errorf("failed to unmarshal genesis state: %v", err)
	}

	certsGenState := types.GetGenesisStateFromAppState(cdc, appState)

	if certsGenState.Certificates.Contains(cert) {
		return errors.Errorf("cannot add already existing certificate")
	}
	certsGenState.Certificates = append(certsGenState.Certificates, cert)

	certsGenStateBz, err := cdc.MarshalJSON(certsGenState)
	if err != nil {
		return errors.Errorf("failed to marshal auth genesis state: %v", err)
	}

	appState[types.ModuleName] = certsGenStateBz

	appStateJSON, err := json.Marshal(appState)
	if err != nil {
		return errors.Errorf("failed to marshal application genesis state: %v", err)
	}

	genDoc.AppState = appStateJSON
	return genutil.ExportGenesisFile(genDoc, genFile)
}

func createAuthPem(cmd *cobra.Command, isServer bool, domains []string) (*types.MsgCreateCertificate, error) {
	clientCtx, err := client.ReadTxCommandFlags(client.GetClientContextFromCmd(cmd), cmd.Flags())
	if err != nil {
		return nil, err
	}

	fromAddress := clientCtx.GetFromAddress()
	// todo operation below needs more digging to ensure security. current implementation is more like example
	//      private key we generate has to be password protected
	//      from user prospective remembering/handling yet another password
	//      would be a subject of obliviousness. instead we utilize account's key
	//      to generate signature of it's address and use it as a password to encrypt
	//      private key.
	//      from security prospective this signature must never be exposed to prevent certificate leak.
	//      from other hand user must never obtain signature of it's own addresses in shell
	//      so yet again - to be discussed
	sig, _, err := clientCtx.Keyring.SignByAddress(fromAddress, fromAddress.Bytes())
	if err != nil {
		return nil, err
	}

	pemFile := clientCtx.HomeDir + "/" + fromAddress.String() + ".pem"

	var priv *ecdsa.PrivateKey

	if priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return nil, err
	}

	nbf := time.Now()
	naf := nbf.Add(time.Hour * 24 * 365)

	if val := cmd.Flag(flagNbf).Value.String(); val != "" {
		nbf, err = time.Parse(time.RFC3339, val)
		if err != nil {
			return nil, err
		}
	}

	if val := cmd.Flag(flagNaf).Value.String(); val != "" {
		if strings.HasSuffix(val, "d") {
			days, err := strconv.ParseUint(strings.TrimSuffix(val, "d"), 10, 32)
			if err != nil {
				return nil, err
			}

			naf = nbf.Add(time.Hour * 24 * time.Duration(days))
		} else {
			naf, err = time.Parse(time.RFC3339, val)
			if err != nil {
				return nil, err
			}
		}
	}

	serialNumber := new(big.Int).SetInt64(time.Now().UTC().UnixNano())

	extKeyUsage := []x509.ExtKeyUsage{
		x509.ExtKeyUsageClientAuth,
	}

	if isServer {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageServerAuth)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: fromAddress.String(),
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  AuthVersionOID,
					Value: "v0.0.1",
				},
			},
		},
		Issuer: pkix.Name{
			CommonName: fromAddress.String(),
		},
		NotBefore:             nbf,
		NotAfter:              naf,
		KeyUsage:              x509.KeyUsageDataEncipherment | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
	}

	if isServer {
		template.PermittedDNSDomainsCritical = true
		template.PermittedDNSDomains = domains
		template.DNSNames = domains
	}

	var certDer []byte
	if certDer, err = x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv); err != nil {
		_ = clientCtx.PrintString(fmt.Sprintf("Failed to create certificate: %v\n", err))
		return nil, err
	}

	var keyDer []byte
	if keyDer, err = x509.MarshalPKCS8PrivateKey(priv); err != nil {
		return nil, err
	}

	var pubKeyDer []byte
	if pubKeyDer, err = x509.MarshalPKIXPublicKey(priv.Public()); err != nil {
		return nil, err
	}

	var blk *pem.Block
	blk, err = x509.EncryptPEMBlock(rand.Reader, types.PemBlkTypeECPrivateKey, keyDer, sig, x509.PEMCipherAES256)
	if err != nil {
		_ = clientCtx.PrintString(fmt.Sprintf("failed to encrypt key file: %v\n", err))
		return nil, err
	}

	var pemOut *os.File
	if pemOut, err = os.OpenFile(pemFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600); err != nil {
		return nil, err
	}

	defer func() {
		if err = pemOut.Close(); err != nil {
			_ = clientCtx.PrintString(fmt.Sprintf("failed to close key file: %v\n", err))
		} else {
			_ = os.Chmod(pemFile, 0400)
		}
	}()

	if err = pem.Encode(pemOut, &pem.Block{Type: types.PemBlkTypeCertificate, Bytes: certDer}); err != nil {
		_ = clientCtx.PrintString(fmt.Sprintf("failed to write certificate to pem file: %v\n", err))
		return nil, err
	}

	if err = pem.Encode(pemOut, blk); err != nil {
		_ = clientCtx.PrintString(fmt.Sprintf("failed to write key to pem file: %v\n", err))
		return nil, err
	}

	msg := &types.MsgCreateCertificate{
		ID: types.CertificateID{
			Owner:  clientCtx.GetFromAddress().String(),
			Serial: serialNumber.String(),
		},
		Cert: pem.EncodeToMemory(&pem.Block{
			Type:  types.PemBlkTypeCertificate,
			Bytes: certDer,
		}),
		Pubkey: pem.EncodeToMemory(&pem.Block{
			Type:  types.PemBlkTypeECPublicKey,
			Bytes: pubKeyDer,
		}),
	}

	if err = msg.ValidateBasic(); err != nil {
		return nil, err
	}

	return msg, nil
}

func doRevoke(cctx client.Context, flags *pflag.FlagSet, cert *x509.Certificate) error {
	msg := &types.MsgRevokeCertificate{
		ID: types.CertificateID{
			Owner:  cert.Subject.CommonName,
			Serial: cert.SerialNumber.String(),
		},
	}

	return tx.GenerateOrBroadcastTxCLI(cctx, flags, msg)
}
