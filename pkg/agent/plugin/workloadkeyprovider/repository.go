package workloadkeyprovider

type Repository struct {
	provider Provider
}

func (r *Repository) GetWorkloadKeyProvider() Provider {
	return r.provider
}

func (r *Repository) SetWorkloadKeyProvider(provider Provider) {
	r.provider = provider
}

func (r *Repository) Clear() {
	r.provider = nil
}
