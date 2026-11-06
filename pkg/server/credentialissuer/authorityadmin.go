package credentialissuer

import "context"

type AuthorityAdmin interface {
	GetCurrentJWTKeySlot() AuthorityState
	GetNextJWTKeySlot() AuthorityState
	PrepareJWTKey(context.Context) error
	RotateJWTKey(context.Context) error
	IsJWTSVIDsDisabled() bool
	GetCurrentX509CASlot() AuthorityState
	GetNextX509CASlot() AuthorityState
	PrepareX509CA(context.Context) error
	RotateX509CA(context.Context) error
	IsUpstreamAuthority() bool
	NotifyTaintedX509Authority(context.Context, string) error
}
