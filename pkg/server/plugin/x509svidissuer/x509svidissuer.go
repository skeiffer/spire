package x509svidissuer

import (
	"context"

	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
)

type X509SVIDIssuer interface {
	catalog.PluginInfo
	IssueX509SVID(context.Context, *issuerv1.IssueX509SVIDRequest) (*issuerv1.IssueX509SVIDResponse, error)
	SubscribeAuthoritySnapshots(context.Context) (AuthoritySnapshotStream, error)
}
