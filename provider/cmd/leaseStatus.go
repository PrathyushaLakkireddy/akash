package cmd

import (
	"context"
	"crypto/tls"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/spf13/cobra"

	cmdcommon "github.com/ovrclk/akash/cmd/common"
	"github.com/ovrclk/akash/provider/gateway"
	cutils "github.com/ovrclk/akash/x/cert/utils"
	mtypes "github.com/ovrclk/akash/x/market/types"
)

func leaseStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lease-status",
		Short: "get lease status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return doLeaseStatus(cmd)
		},
	}

	addLeaseFlags(cmd)

	return cmd
}

func doLeaseStatus(cmd *cobra.Command) error {
	cctx, err := client.ReadTxCommandFlags(client.GetClientContextFromCmd(cmd), cmd.Flags())
	if err != nil {
		return err
	}

	prov, err := providerFromFlags(cmd.Flags())
	if err != nil {
		return err
	}

	dseq, gseq, oseq, err := parseLeaseFromFlags(cmd.Flags())
	if err != nil {
		return err
	}

	lid := mtypes.LeaseID{
		DSeq:     dseq,
		GSeq:     gseq,
		OSeq:     oseq,
		Provider: prov.String(),
	}

	cert, err := cutils.LoadCertificateFromFrom(cctx.HomeDir, cctx.FromAddress, cctx.Keyring)
	if err != nil {
		return err
	}

	gclient, err := gateway.NewClient(cctx, prov, []tls.Certificate{cert})
	if err != nil {
		return err
	}

	result, err := gclient.LeaseStatus(context.Background(), lid)
	if err != nil {
		return showErrorToUser(err)
	}
	return cmdcommon.PrintJSON(cctx, result)
}
