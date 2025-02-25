package rawapi

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/NilFoundation/nil/nil/common"
	"github.com/NilFoundation/nil/nil/common/check"
	"github.com/NilFoundation/nil/nil/internal/network"
	"github.com/NilFoundation/nil/nil/internal/types"
	"github.com/NilFoundation/nil/nil/services/rpc/rawapi/pb"
	"github.com/rs/zerolog"
)

var errRequestHandlerCreation = errors.New("failed to create request handler")

type NetworkTransportProtocolRo interface {
	GetBlockHeader(request pb.BlockRequest) pb.RawBlockResponse
	GetFullBlockData(request pb.BlockRequest) pb.RawFullBlockResponse
	GetBlockTransactionCount(request pb.BlockRequest) pb.Uint64Response

	GetInTransaction(pb.TransactionRequest) pb.TransactionResponse
	GetInTransactionReceipt(pb.Hash) pb.ReceiptResponse

	GetBalance(request pb.AccountRequest) pb.BalanceResponse
	GetCode(request pb.AccountRequest) pb.CodeResponse
	GetTokens(request pb.AccountRequest) pb.TokensResponse
	GetTransactionCount(pb.AccountRequest) pb.Uint64Response
	GetContract(request pb.AccountRequest) pb.RawContractResponse

	Call(pb.CallRequest) pb.CallResponse

	GasPrice() pb.GasPriceResponse
	GetShardIdList() pb.ShardIdListResponse
	GetNumShards() pb.Uint64Response
}

// NetworkTransportProtocol is a helper interface for associating the argument and result types of Api methods
// with their Protobuf representations.
type NetworkTransportProtocol interface {
	NetworkTransportProtocolRo
	SendTransaction(pb.SendTransactionRequest) pb.SendTransactionResponse
}

func SetRawApiRequestHandlers(ctx context.Context, shardId types.ShardId, api ShardApi, manager *network.Manager, readonly bool, logger zerolog.Logger) error {
	var protocolInterfaceType, apiType reflect.Type
	if readonly {
		protocolInterfaceType = reflect.TypeFor[NetworkTransportProtocolRo]()
		apiType = reflect.TypeFor[ShardApiRo]()
	} else {
		protocolInterfaceType = reflect.TypeFor[NetworkTransportProtocol]()
		apiType = reflect.TypeFor[ShardApi]()
	}
	return setRawApiRequestHandlers(ctx, protocolInterfaceType, apiType, api, shardId, "rawapi", manager, logger)
}

func getRawApiRequestHandlers(protocolInterfaceType, apiType reflect.Type, api any, shardId types.ShardId, apiName string) (map[network.ProtocolID]network.RequestHandler, error) {
	check.PanicIfNotf(reflect.ValueOf(api).Type().Implements(apiType), "api does not implement %s", apiType)
	requestHandlers := make(map[network.ProtocolID]network.RequestHandler)
	codec, err := newApiCodec(apiType, protocolInterfaceType)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errRequestHandlerCreation, err)
	}

	apiValue := reflect.ValueOf(api)
	for method := range common.Filter(iterMethods(apiType), isExportedMethod) {
		methodName := method.Name
		methodCodec, ok := codec[methodName]
		check.PanicIfNotf(ok, "Appropriate codec is not found for method %s", methodName)

		protocol := network.ProtocolID(fmt.Sprintf("/shard/%d/%s/%s", shardId, apiName, methodName))
		requestHandlers[protocol] = makeRequestHandler(apiValue.MethodByName(methodName), methodCodec)
	}
	return requestHandlers, nil
}

func setRawApiRequestHandlers(ctx context.Context, protocolInterfaceType, apiType reflect.Type, api any, shardId types.ShardId, apiName string, manager *network.Manager, logger zerolog.Logger) error {
	requestHandlers, err := getRawApiRequestHandlers(protocolInterfaceType, apiType, api, shardId, apiName)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to create request handlers")
		return err
	}
	for name, handler := range requestHandlers {
		manager.SetRequestHandler(ctx, name, handler)
	}
	return nil
}

func makeRequestHandler(apiMethod reflect.Value, codec *methodCodec) network.RequestHandler {
	return func(ctx context.Context, request []byte) ([]byte, error) {
		unpackedArguments, err := codec.unpackRequest(request)
		if err != nil {
			return codec.packError(err), nil
		}

		apiArguments := []reflect.Value{reflect.ValueOf(ctx)}
		apiArguments = append(apiArguments, unpackedArguments...)
		apiCallResults := apiMethod.Call(apiArguments)

		return codec.packResponse(apiCallResults...)
	}
}
