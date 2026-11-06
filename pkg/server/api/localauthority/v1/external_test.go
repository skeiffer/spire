package localauthority_test

import (
	"context"
	"errors"
	"testing"

	"github.com/sirupsen/logrus"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	localauthority "github.com/spiffe/spire/pkg/server/api/localauthority/v1"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/credentialissuer"
	"github.com/spiffe/spire/proto/private/server/journal"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestExternalX509AdministrationIsGatedBeforeDependencies(t *testing.T) {
	ctx := rpccontext.WithLogger(t.Context(), logrus.New())
	s := localauthority.New(localauthority.Config{ExternalX509: true})
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{name: "get", call: func() error {
			_, err := s.GetX509AuthorityState(ctx, new(localauthorityv1.GetX509AuthorityStateRequest))
			return err
		}},
		{name: "prepare", call: func() error {
			_, err := s.PrepareX509Authority(ctx, new(localauthorityv1.PrepareX509AuthorityRequest))
			return err
		}},
		{name: "activate", call: func() error {
			_, err := s.ActivateX509Authority(ctx, new(localauthorityv1.ActivateX509AuthorityRequest))
			return err
		}},
		{name: "taint", call: func() error {
			_, err := s.TaintX509Authority(ctx, new(localauthorityv1.TaintX509AuthorityRequest))
			return err
		}},
		{name: "revoke", call: func() error {
			_, err := s.RevokeX509Authority(ctx, new(localauthorityv1.RevokeX509AuthorityRequest))
			return err
		}},
		{name: "taint upstream", call: func() error {
			_, err := s.TaintX509UpstreamAuthority(ctx, new(localauthorityv1.TaintX509UpstreamAuthorityRequest))
			return err
		}},
		{name: "revoke upstream", call: func() error {
			_, err := s.RevokeX509UpstreamAuthority(ctx, new(localauthorityv1.RevokeX509UpstreamAuthorityRequest))
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, codes.Unimplemented, status.Code(tc.call()))
		})
	}
}

func TestJWTActivationDoesNotAcknowledgeFailedDurableCommit(t *testing.T) {
	ctx := rpccontext.WithLogger(t.Context(), logrus.New())
	s := localauthority.New(localauthority.Config{CAManager: &failedActivation{}})
	response, err := s.ActivateJWTAuthority(ctx, &localauthorityv1.ActivateJWTAuthorityRequest{AuthorityId: "prepared"})
	require.Nil(t, response)
	require.Equal(t, codes.Internal, status.Code(err))
	require.ErrorContains(t, err, "durable commit failed")
}

type failedActivation struct {
	credentialissuer.AuthorityAdmin
}

func (*failedActivation) IsJWTSVIDsDisabled() bool { return false }
func (*failedActivation) GetNextJWTKeySlot() credentialissuer.AuthorityState {
	return credentialissuer.AuthorityView{ID: "prepared", State: journal.Status_PREPARED}
}
func (*failedActivation) RotateJWTKey(context.Context) error {
	return errors.New("durable commit failed")
}
