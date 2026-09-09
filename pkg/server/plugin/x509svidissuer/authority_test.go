package x509svidissuer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestAuthorityStoreRolloverAndTaint(t *testing.T) {
	now := time.Now().UTC()
	root1 := makeRoot(t, "root-1", now.Add(-time.Hour), now.Add(2*time.Hour))
	root2 := makeRoot(t, "root-2", now.Add(-time.Hour), now.Add(4*time.Hour))
	store := NewAuthorityStore(time.Minute)

	requireNoError(t, store.Publish(Snapshot{Version: "v1", Roots: []*x509.Certificate{root1}}))
	requireNoError(t, store.Activate("v1", now))
	if got := store.ActiveVersion(); got != "v1" {
		t.Fatalf("active version = %q, want v1", got)
	}

	requireNoError(t, store.Publish(Snapshot{Version: "v2", Roots: []*x509.Certificate{root1, root2}}))
	requireNoError(t, store.Activate("v2", now))
	if err := store.Remove("v1", now.Add(30*time.Second)); !errors.Is(err, ErrRetentionWindow) {
		t.Fatalf("expected retention error, got %v", err)
	}
	requireNoError(t, store.Remove("v1", now.Add(2*time.Minute)))

	store.Taint("v2", errors.New("issuer unhealthy"))
	if _, err := store.Active(); !errors.Is(err, ErrAuthorityTainted) {
		t.Fatalf("expected tainted authority error, got %v", err)
	}
}

func TestAuthorityVersionsAreImmutableAndActivationRequiresOverlap(t *testing.T) {
	now := time.Now().UTC()
	root1 := makeRoot(t, "root-1", now.Add(-time.Hour), now.Add(time.Hour))
	root2 := makeRoot(t, "root-2", now.Add(-time.Hour), now.Add(time.Hour))
	store := NewAuthorityStore(time.Minute)

	requireNoError(t, store.Publish(Snapshot{Version: "v1", Roots: []*x509.Certificate{root1}}))
	if err := store.Publish(Snapshot{Version: "v1", Roots: []*x509.Certificate{root2}}); !errors.Is(err, ErrVersionReused) {
		t.Fatalf("expected immutable version error, got %v", err)
	}
	requireNoError(t, store.Activate("v1", now))
	requireNoError(t, store.Publish(Snapshot{Version: "v2", Roots: []*x509.Certificate{root2}}))
	if err := store.Activate("v2", now); !errors.Is(err, ErrNoAuthorityOverlap) {
		t.Fatalf("expected overlap error, got %v", err)
	}
}

func makeRoot(t *testing.T, cn string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	requireNoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(notAfter.UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	requireNoError(t, err)
	cert, err := x509.ParseCertificate(der)
	requireNoError(t, err)
	return cert
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
