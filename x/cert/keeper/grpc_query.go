package keeper

import (
	"context"
	"math/big"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkquery "github.com/cosmos/cosmos-sdk/types/query"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ovrclk/akash/x/cert/types"
)

// Querier is used as Keeper will have duplicate methods if used directly, and gRPC names take precedence over keeper
type Querier struct {
	Keeper
}

var _ types.QueryServer = Querier{}

func (q Querier) Certificates(c context.Context, req *types.QueryCertificatesRequest) (*types.QueryCertificatesResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}

	var certificates types.Certificates
	var pageRes *sdkquery.PageResponse
	var err error

	ctx := sdk.UnwrapSDKContext(c)
	store := ctx.KVStore(q.skey)

	state := types.CertificateStateInvalid
	if req.Filter.State != "" {
		vl, exists := types.Certificate_State_value[req.Filter.State]

		if !exists {
			return nil, status.Error(codes.InvalidArgument, "invalid state value")
		}

		state = types.Certificate_State(vl)
	}

	if req.Filter.Owner != "" {
		var owner sdk.Address
		if owner, err = sdk.AccAddressFromBech32(req.Filter.Owner); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}

		if req.Filter.Serial != "" {
			serial, valid := new(big.Int).SetString(req.Filter.Serial, 10)
			if !valid {
				return nil, status.Error(codes.InvalidArgument, "invalid serial number")
			}

			cert, found := q.GetCertificateByID(ctx, types.CertID{
				Owner:  owner,
				Serial: *serial,
			})
			if !found {
				return nil, status.Error(codes.NotFound, types.ErrCertificateNotFound.Error())
			}

			if filterCertByState(state, cert.State) {
				certificates = append(certificates, cert)
			}

			certificates = append(certificates, cert)
		} else {
			pageRes, err = sdkquery.Paginate(store, req.Pagination, func(key []byte, value []byte) error {
				var cert types.Certificate
				if e := q.cdc.UnmarshalBinaryBare(value, &cert); e != nil {
					return err
				}

				if filterCertByState(state, cert.State) {
					certificates = append(certificates, cert)
				}
				return nil
			})
		}
	} else {
		pageRes, err = sdkquery.Paginate(store, req.Pagination, func(key []byte, value []byte) error {
			var cert types.Certificate
			if e := q.cdc.UnmarshalBinaryBare(value, &cert); e != nil {
				return err
			}

			if filterCertByState(state, cert.State) {
				certificates = append(certificates, cert)
			}
			return nil
		})
	}

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryCertificatesResponse{
		Certificates: certificates,
		Pagination:   pageRes,
	}, nil
}

func filterCertByState(state types.Certificate_State, cert types.Certificate_State) bool {
	return (state == types.CertificateStateInvalid) || (cert == state)
}
