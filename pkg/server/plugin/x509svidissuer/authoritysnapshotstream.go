package x509svidissuer

import issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"

type AuthoritySnapshotStream interface {
	Recv() (*issuerv1.AuthoritySnapshot, error)
}
