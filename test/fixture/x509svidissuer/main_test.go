package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

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

func TestProviderStateSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	first, err := loadAuthorities(dir, time.Hour)
	require.NoError(t, err)
	second, err := loadAuthorities(dir, time.Hour)
	require.NoError(t, err)
	for version, authority := range first {
		require.Equal(t, authority.cert.Raw, second[version].cert.Raw)
		require.True(t, authority.key.Equal(second[version].key))
	}
	require.NotEqual(t, first[authorityVersion].cert.Raw, first[successorVersion].cert.Raw)
}
