package cmd

import (
	"github.com/cosmos/cosmos-sdk/client/flags"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func addCmdFlags(cmd *cobra.Command) {
	cmd.Flags().String("provider", "", "provider")
	cmd.Flags().Uint64("dseq", 0, "deployment sequence")
	cmd.Flags().String(flags.FlagHome, "", "the application home directory")
	cmd.Flags().String(flags.FlagFrom, "", "name or address of private key with which to sign")
	cmd.Flags().String(flags.FlagKeyringBackend, flags.DefaultKeyringBackend, "select keyring's backend (os|file|kwallet|pass|test)")

	if err := cmd.MarkFlagRequired("provider"); err != nil {
		panic(err.Error())
	}

	if err := cmd.MarkFlagRequired("dseq"); err != nil {
		panic(err.Error())
	}

	if err := cmd.MarkFlagRequired(flags.FlagHome); err != nil {
		panic(err.Error())
	}

	if err := cmd.MarkFlagRequired(flags.FlagFrom); err != nil {
		panic(err.Error())
	}
}

func addLeaseFlags(cmd *cobra.Command) {
	addCmdFlags(cmd)

	cmd.Flags().Uint32("gseq", 1, "group sequence")
	cmd.Flags().Uint32("oseq", 1, "order sequence")
}

func addServiceFlags(cmd *cobra.Command) {
	addLeaseFlags(cmd)

	cmd.Flags().String(FlagService, "", "name of service to query")
	if err := cmd.MarkFlagRequired(FlagService); err != nil {
		panic(err.Error())
	}
}

func dseqFromFlags(flags *pflag.FlagSet) (uint64, error) {
	return flags.GetUint64("dseq")
}

func providerFromFlags(flags *pflag.FlagSet) (sdk.Address, error) {
	provider, err := flags.GetString("provider")
	if err != nil {
		return nil, err
	}
	addr, err := sdk.AccAddressFromBech32(provider)
	if err != nil {
		return nil, err
	}

	return addr, nil
}

func parseLeaseFromFlags(flags *pflag.FlagSet) (uint64, uint32, uint32, error) {
	dseq, err := flags.GetUint64("dseq")
	if err != nil {
		return 0, 0, 0, err
	}

	gseq, err := flags.GetUint32("gseq")
	if err != nil {
		return 0, 0, 0, err
	}

	oseq, err := flags.GetUint32("oseq")
	if err != nil {
		return 0, 0, 0, err
	}

	return dseq, gseq, oseq, nil
}
