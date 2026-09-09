package x509svidissuer

import (
	"context"

	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"github.com/spiffe/spire/pkg/common/plugin"
)

type V1 struct {
	plugin.Facade
	issuerv1.X509SVIDIssuerPluginClient
}

func (v *V1) IssueX509SVID(ctx context.Context, req *issuerv1.IssueX509SVIDRequest) (*issuerv1.IssueX509SVIDResponse, error) {
	resp, err := v.X509SVIDIssuerPluginClient.IssueX509SVID(ctx, req)
	if err != nil {
		return nil, v.WrapErr(err)
	}
	return resp, nil
}

func (v *V1) SubscribeAuthoritySnapshots(ctx context.Context) (AuthoritySnapshotStream, error) {
	stream, err := v.X509SVIDIssuerPluginClient.SubscribeAuthoritySnapshots(ctx, &issuerv1.SubscribeAuthoritySnapshotsRequest{})
	if err != nil {
		return nil, v.WrapErr(err)
	}
	return stream, nil
}
