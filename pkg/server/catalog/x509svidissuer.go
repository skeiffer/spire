package catalog

import (
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/x509svidissuer"
)

type x509SVIDIssuerRepository struct {
	x509svidissuer.Repository
}

func (repo *x509SVIDIssuerRepository) Binder() any {
	return repo.SetX509SVIDIssuer
}

func (repo *x509SVIDIssuerRepository) Constraints() catalog.Constraints {
	return catalog.MaybeOne()
}

func (repo *x509SVIDIssuerRepository) Versions() []catalog.Version {
	return []catalog.Version{x509SVIDIssuerV1{}}
}

func (repo *x509SVIDIssuerRepository) BuiltIns() []catalog.BuiltIn {
	return nil
}

type x509SVIDIssuerV1 struct{}

func (x509SVIDIssuerV1) New() catalog.Facade        { return new(x509svidissuer.V1) }
func (x509SVIDIssuerV1) Deprecated() (bool, string) { return false, "" }
