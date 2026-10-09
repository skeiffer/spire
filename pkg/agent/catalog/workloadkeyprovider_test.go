package catalog_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/stretchr/testify/require"
)

func TestWorkloadKeyProviderUsesOptionalExternalCatalogRepository(t *testing.T) {
	repo := new(catalog.Repository)
	require.Nil(t, repo.GetWorkloadKeyProvider())

	path := filepath.Join("workloadkeyprovider.go")
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(contents), "catalog.MaybeOne()")
	require.Contains(t, string(contents), "return nil")
}
