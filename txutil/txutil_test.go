package txutil_test

import (
	"testing"

	"github.com/ovrclk/akash/testutil"
	"github.com/ovrclk/akash/txutil"
	"github.com/ovrclk/akash/types"
	"github.com/ovrclk/akash/types/base"
	"github.com/stretchr/testify/require"
)

func TestTxBuilder_KeyManager(t *testing.T) {

	const nonce = 1

	manager := testutil.KeyManager(t)

	keyfrom, _, err := manager.Create("keyfrom", testutil.KeyPasswd, testutil.KeyAlgo)
	require.NoError(t, err)

	keyto, _, err := manager.Create("keyto", testutil.KeyPasswd, testutil.KeyAlgo)
	require.NoError(t, err)

	send := &types.TxSend{
		From:   base.Bytes(keyfrom.Address),
		To:     base.Bytes(keyto.Address),
		Amount: 100,
	}

	txbytes, err := txutil.BuildTx(txutil.NewKeystoreSigner(manager, keyfrom.Name, testutil.KeyPasswd), nonce, send)

	txp, err := txutil.NewTxProcessor(txbytes)
	require.NoError(t, err)

	require.NoError(t, txp.Validate())

	tx := txp.GetTx()

	require.Equal(t, []byte(keyfrom.Address), tx.Key.Address())

	rsend := tx.Payload.GetTxSend()
	require.NotNil(t, rsend)

	require.Equal(t, rsend.From, send.From)
	require.Equal(t, rsend.To, send.To)
	require.Equal(t, rsend.Amount, send.Amount)
}

func TestTxBuilder_KeySigner(t *testing.T) {
	const nonce = 1

	keyfrom := testutil.PrivateKey(t)
	keyto := testutil.PrivateKey(t)

	send := &types.TxSend{
		From:   base.Bytes(keyfrom.PubKey().Address()),
		To:     base.Bytes(keyto.PubKey().Address()),
		Amount: 100,
	}

	txbytes, err := txutil.BuildTx(txutil.NewPrivateKeySigner(keyfrom), nonce, send)

	txp, err := txutil.NewTxProcessor(txbytes)
	require.NoError(t, err)

	require.NoError(t, txp.Validate())

	tx := txp.GetTx()

	require.Equal(t, []byte(keyfrom.PubKey().Address()), tx.Key.Address())

	rsend := tx.Payload.GetTxSend()
	require.NotNil(t, rsend)

	require.Equal(t, rsend.From, send.From)
	require.Equal(t, rsend.To, send.To)
	require.Equal(t, rsend.Amount, send.Amount)

}