package catalog

import (
	"github.com/spiffe/spire/pkg/agent/plugin/workloadkeyprovider"
	"github.com/spiffe/spire/pkg/common/catalog"
)

type workloadKeyProviderRepository struct {
	workloadkeyprovider.Repository
}

func (repo *workloadKeyProviderRepository) Binder() any {
	return repo.SetWorkloadKeyProvider
}

func (repo *workloadKeyProviderRepository) Constraints() catalog.Constraints {
	return catalog.MaybeOne()
}

func (repo *workloadKeyProviderRepository) Versions() []catalog.Version {
	return []catalog.Version{workloadKeyProviderV1{}}
}

func (repo *workloadKeyProviderRepository) BuiltIns() []catalog.BuiltIn {
	return nil
}

type workloadKeyProviderV1 struct{}

func (workloadKeyProviderV1) New() catalog.Facade {
	return new(workloadkeyprovider.V1)
}

func (workloadKeyProviderV1) Deprecated() (bool, string) {
	return false, ""
}
