package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestIssuanceFailureControl(t *testing.T) {
	failureFile := filepath.Join(t.TempDir(), "fail-issuance")
	t.Setenv("SPIRE_TEST_ISSUER_FAILURE_FILE", failureFile)
	p := new(plugin)
	req := &issuerv1.IssueX509SVIDRequest{}

	_, err := p.IssueX509SVID(context.Background(), req)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))

	require.NoError(t, os.WriteFile(failureFile, nil, 0o600))
	_, err = p.IssueX509SVID(context.Background(), req)
	require.Equal(t, codes.Unavailable, status.Code(err))
	require.Contains(t, err.Error(), "fixture issuance disabled")
}
