package fakeagentcatalog

import (
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadkeyprovider"
)

func New() *Catalog {
	return new(Catalog)
}

type Catalog struct {
	keyManagerRepository
	nodeAttestorRepository
	svidStoreRepository
	workloadAttestorRepository
	workloadKeyProviderRepository
}

// We need distinct type names to embed in the Catalog above, since the types
// we want to actually embed are all named the same.
type keyManagerRepository struct{ keymanager.Repository }
type nodeAttestorRepository struct{ nodeattestor.Repository }
type svidStoreRepository struct{ svidstore.Repository }
type workloadAttestorRepository struct{ workloadattestor.Repository }
type workloadKeyProviderRepository struct{ workloadkeyprovider.Repository }
