package baseapp

import (
	"errors"
	"fmt"

	"github.com/cometbft/cometbft/abci/types"

	"cosmossdk.io/core/genesis"
	storetypes "cosmossdk.io/store/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

var _ genesis.TxHandler = (*BaseApp)(nil)

// ExecuteGenesisTxWithContext runs the normal transaction pipeline in the same
// store branch as module initialization. InitGenesis may use a child cache that
// is not yet visible to the BaseApp's finalize-block state. Keep the original
// BaseApp state unchanged: only this value receiver's state pointer is replaced.
// The caller owns committing or discarding the supplied cache.
func (ba BaseApp) ExecuteGenesisTxWithContext(ctx sdk.Context, tx []byte) error {
	if ctx.IsZero() {
		return fmt.Errorf("missing genesis transaction context")
	}
	ms, ok := ctx.MultiStore().(storetypes.CacheMultiStore)
	if !ok {
		return fmt.Errorf("genesis transaction context must use a cache multistore")
	}
	ba.finalizeBlockState = &state{ms: ms, ctx: ctx}
	return ba.ExecuteGenesisTx(tx)
}

// ExecuteGenesisTx implements genesis.GenesisState from
// cosmossdk.io/core/genesis to set initial state in genesis
func (ba BaseApp) ExecuteGenesisTx(tx []byte) error {
	res := ba.deliverTx(tx)

	if res.Code != types.CodeTypeOK {
		return errors.New(res.Log)
	}

	return nil
}
