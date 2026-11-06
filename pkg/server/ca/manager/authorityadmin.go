package manager

import (
	"context"

	"github.com/spiffe/spire/pkg/server/credentialissuer"
)

type authorityAdmin struct{ *Manager }

func NewAuthorityAdmin(m *Manager) credentialissuer.AuthorityAdmin {
	return authorityAdmin{m}
}

func authorityView(slot Slot) credentialissuer.AuthorityState {
	return credentialissuer.AuthorityView{
		ID: slot.AuthorityID(), UpstreamID: slot.UpstreamAuthorityID(),
		ExpiresAt: slot.NotAfter(), State: slot.Status(),
	}
}

func (a authorityAdmin) GetCurrentJWTKeySlot() credentialissuer.AuthorityState {
	a.jwtKeyMutex.RLock()
	defer a.jwtKeyMutex.RUnlock()
	return authorityView(a.currentJWTKey)
}

func (a authorityAdmin) GetNextJWTKeySlot() credentialissuer.AuthorityState {
	a.jwtKeyMutex.RLock()
	defer a.jwtKeyMutex.RUnlock()
	return authorityView(a.nextJWTKey)
}

func (a authorityAdmin) GetCurrentX509CASlot() credentialissuer.AuthorityState {
	a.x509CAMutex.RLock()
	defer a.x509CAMutex.RUnlock()
	return authorityView(a.currentX509CA)
}

func (a authorityAdmin) GetNextX509CASlot() credentialissuer.AuthorityState {
	a.x509CAMutex.RLock()
	defer a.x509CAMutex.RUnlock()
	return authorityView(a.nextX509CA)
}

func (a authorityAdmin) RotateJWTKey(ctx context.Context) error {
	a.Manager.RotateJWTKey(ctx)
	return nil
}
