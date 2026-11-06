package credentialissuer

import "context"

type TokenIssuer interface {
	SignWorkloadJWTSVID(context.Context, WorkloadJWTSVIDParams) (string, error)
	SignWorkloadWITSVID(context.Context, WorkloadWITSVIDParams) (string, error)
	IsJWTSVIDsDisabled() bool
	IsWITSVIDsDisabled() bool
}
