package credentialissuer

import (
	"time"

	"github.com/spiffe/spire/proto/private/server/journal"
)

type AuthorityState interface {
	AuthorityID() string
	UpstreamAuthorityID() string
	NotAfter() time.Time
	Status() journal.Status
}

type AuthorityView struct {
	ID         string
	UpstreamID string
	ExpiresAt  time.Time
	State      journal.Status
}

func (v AuthorityView) AuthorityID() string         { return v.ID }
func (v AuthorityView) UpstreamAuthorityID() string { return v.UpstreamID }
func (v AuthorityView) NotAfter() time.Time         { return v.ExpiresAt }
func (v AuthorityView) Status() journal.Status      { return v.State }
