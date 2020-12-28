package cmd

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	cmdcommon "github.com/ovrclk/akash/cmd/common"
	"github.com/ovrclk/akash/provider/gateway"
	cutils "github.com/ovrclk/akash/x/cert/utils"
	mtypes "github.com/ovrclk/akash/x/market/types"
)

func serviceLogsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "service-logs",
		Short:        "get service status",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return doServiceLogs(cmd)
		},
	}

	addServiceFlags(cmd)

	cmd.Flags().BoolP("follow", "f", false, "Specify if the logs should be streamed. Defaults to false")
	cmd.Flags().Int64P("tail", "t", -1, "The number of lines from the end of the logs to show. Defaults to -1")
	cmd.Flags().String("format", "text", "Output format text|json. Defaults to text")

	return cmd
}

func doServiceLogs(cmd *cobra.Command) error {
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

	outputFormat, err := cmd.Flags().GetString("format")
	if err != nil {
		return err
	}

	if outputFormat != "text" && outputFormat != "json" {
		return errors.Errorf("invalid output format %s", outputFormat)
	}

	follow, err := cmd.Flags().GetBool("follow")
	if err != nil {
		return err
	}

	tailLines, err := cmd.Flags().GetInt64("tail")
	if err != nil {
		return err
	}

	if tailLines < -1 {
		return errors.Errorf("tail flag supplied with invalid value. must be >= -1")
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

	result, err := gclient.ServiceLogs(context.Background(), lid, svcName, follow, tailLines)
	if err != nil {
		return showErrorToUser(err)
	}

	printFn := func(msg gateway.ServiceLogMessage) error {
		fmt.Printf("[%s] %s\n", msg.Name, msg.Message)
		return nil
	}

	if outputFormat == "json" {
		printFn = func(msg gateway.ServiceLogMessage) error {
			return cmdcommon.PrintJSON(cctx, msg)
		}
	}

	for res := range result.Stream {
		err = printFn(res)
		if err != nil {
			return err
		}
	}

	select {
	case msg, ok := <-result.OnClose:
		if ok && msg != "" {
			_ = cctx.PrintString(msg)
			_ = cctx.PrintString("\n")
		}
	}
	return nil
}
