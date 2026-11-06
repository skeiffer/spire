package credentialissuer

import (
	"context"

	"github.com/spiffe/spire/proto/spire/common"
)

type TokenPublisher interface {
	PublishJWTKey(context.Context, *common.PublicKey) ([]*common.PublicKey, error)
	PublishWITKey(context.Context, *common.PublicKey) ([]*common.PublicKey, error)
}
