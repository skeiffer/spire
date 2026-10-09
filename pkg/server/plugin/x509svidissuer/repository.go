package x509svidissuer

type Repository struct {
	issuer X509SVIDIssuer
}

func (r *Repository) GetX509SVIDIssuer() (X509SVIDIssuer, bool) {
	return r.issuer, r.issuer != nil
}

func (r *Repository) SetX509SVIDIssuer(issuer X509SVIDIssuer) {
	r.issuer = issuer
}

func (r *Repository) Clear() {
	r.issuer = nil
}
