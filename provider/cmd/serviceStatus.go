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

const (
	FlagService  = "service"
	FlagProvider = "provider"
	FlagDSeq     = "dseq"
)

func serviceStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "service-status",
		Short:        "get service status",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return doServiceStatus(cmd)
		},
	}

	addServiceFlags(cmd)

	return cmd
}

func doServiceStatus(cmd *cobra.Command) error {
	cctx, err := client.ReadTxCommandFlags(client.GetClientContextFromCmd(cmd), cmd.Flags())
	if err != nil {
		return err
	}

	svcName, err := cmd.Flags().GetString(FlagService)
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

	result, err := gclient.ServiceStatus(context.Background(), lid, svcName)
	if err != nil {
		return showErrorToUser(err)
	}

	return cmdcommon.PrintJSON(cctx, result)
}
