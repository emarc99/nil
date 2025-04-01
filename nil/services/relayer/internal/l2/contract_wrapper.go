package l2

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"

	"github.com/NilFoundation/nil/nil/client"
	"github.com/NilFoundation/nil/nil/common"
	"github.com/NilFoundation/nil/nil/common/logging"
	"github.com/NilFoundation/nil/nil/internal/abi"
	"github.com/NilFoundation/nil/nil/internal/types"
	"github.com/ethereum/go-ethereum/crypto"
)

type ContractConfig struct {
	Endpoint            string
	SmartAccountAddress string
	ContractAddress     string
	PrivateKeyPath      string
	ContractABIPath     string

	// Testing only
	DebugMode        bool
	SmartAccountSalt string
	FaucetAddress    string
}

func DefaultContractConfig() *ContractConfig {
	return &ContractConfig{
		PrivateKeyPath:  "relayer_key.ecdsa",
		DebugMode:       false,
		ContractABIPath: "l2_bridge_messenger_abi.json",
	}
}

func (cfg *ContractConfig) Validate() error {
	if len(cfg.Endpoint) == 0 {
		return errors.New("empty L2 endpoint")
	}
	if len(cfg.SmartAccountAddress) == 0 {
		return errors.New("empty relayer smart account address")
	}
	if len(cfg.PrivateKeyPath) == 0 {
		return errors.New("empty relayer private key file path")
	}
	if len(cfg.ContractAddress) == 0 {
		return errors.New("empty L2BridgeMessenger contract address")
	}
	if len(cfg.ContractABIPath) == 0 {
		return errors.New("empty L2BridgeMessenger contract ABI path")
	}
	if cfg.DebugMode && len(cfg.FaucetAddress) == 0 {
		return errors.New("faucet address is required when generating a new key")
	}
	return nil
}

type L2Contract interface {
	RelayMessage(ctx context.Context, event *Event) (common.Hash, error)
}

type l2ContractWrapper struct {
	nilClient        client.Client
	privateKey       *ecdsa.PrivateKey
	smartAccountAddr types.Address
	contractAddr     types.Address
	abi              abi.ABI
	logger           logging.Logger
}

var _ L2Contract = (*l2ContractWrapper)(nil)

func NewL2ContractWrapper(
	ctx context.Context,
	config *ContractConfig,
	nilClient client.Client,
	logger logging.Logger,
) (*l2ContractWrapper, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	smartAccountAddr := types.HexToAddress(config.SmartAccountAddress)
	contractAddr := types.HexToAddress(config.ContractAddress)

	smartAccountExists, err := checkIfContractExists(ctx, nilClient, smartAccountAddr)
	if err != nil {
		return nil, err
	}
	if !smartAccountExists {
		return nil, fmt.Errorf("smart account %s does not exist", smartAccountAddr)
	}

	l2ContractExists, err := checkIfContractExists(ctx, nilClient, contractAddr)
	if err != nil {
		return nil, err
	}
	if !l2ContractExists {
		logger.Warn().
			Stringer("contract_address", contractAddr).
			Msg("looks like L2 contract is not deployed")
	}

	abiFile, err := os.Open(config.ContractABIPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open '%s' L2 ABI file: %w", config.ContractABIPath, err)
	}
	defer abiFile.Close()

	contractABI, err := abi.JSON(abiFile)
	if err != nil {
		return nil, fmt.Errorf("failed to decode L2 ABI: %w", err)
	}

	pk, err := crypto.LoadECDSA(config.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	return &l2ContractWrapper{
		nilClient:        nilClient,
		privateKey:       pk,
		smartAccountAddr: smartAccountAddr,
		contractAddr:     contractAddr,
		abi:              contractABI,
		logger:           logger,
	}, nil
}

func (w *l2ContractWrapper) RelayMessage(
	ctx context.Context,
	evt *Event,
) (common.Hash, error) {
	const methodName = "relayMessage"
	calldata, err := w.abi.Pack(methodName,
		evt.Sender,
		evt.Target,
		evt.Type,
		evt.Value,
		evt.Nonce,
		evt.Message,
	)
	if err != nil {
		return common.EmptyHash, err
	}

	w.logger.Trace().Stringer("event_hash", evt.Hash).Msg("relaying event")

	return client.SendTransactionViaSmartAccount(
		ctx,
		w.nilClient,
		w.smartAccountAddr,
		calldata,
		evt.FeePack,
		evt.L2Limit,
		nil,
		w.contractAddr,
		w.privateKey,
		false,
	)
}
