package x509svidissuer

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
)

func TestGenericIssuerImplementationHasNoProductAdapterDependencies(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test location")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "..", "..", ".."))
	paths := []string{
		filepath.Join(repoRoot, "pkg", "server", "ca", "ca.go"),
		filepath.Join(repoRoot, "pkg", "server", "server.go"),
		filepath.Join(repoRoot, "pkg", "server", "catalog", "x509svidissuer.go"),
		filepath.Join(repoRoot, "pkg", "server", "plugin", "x509svidissuer"),
	}
	sdkFunction := runtime.FuncForPC(reflect.ValueOf(issuerv1.NewX509SVIDIssuerClient).Pointer())
	if sdkFunction == nil {
		t.Fatal("cannot resolve Plugin SDK package location")
	}
	sdkFile, _ := sdkFunction.FileLine(sdkFunction.Entry())
	paths = append(paths, filepath.Dir(sdkFile))
	forbidden := regexp.MustCompile(`(?i)\b(pki-?r|cauldron|azurehse|hse[_-]?(http|auth|policy|retry|idempotency|adapter|endpoint))\b`)
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() {
			assertNoForbiddenImplementationText(t, path, forbidden)
			continue
		}
		err = filepath.WalkDir(path, func(candidate string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(candidate, ".go") || strings.HasSuffix(candidate, "_test.go") {
				return nil
			}
			assertNoForbiddenImplementationText(t, candidate, forbidden)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func assertNoForbiddenImplementationText(t *testing.T, path string, forbidden *regexp.Regexp) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if match := forbidden.Find(content); match != nil {
		t.Errorf("%s contains forbidden product adapter identifier %q", path, match)
	}
}
