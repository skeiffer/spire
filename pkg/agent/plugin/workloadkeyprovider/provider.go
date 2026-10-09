package workloadkeyprovider

import (
	"context"
	"crypto"
)

type GenerateRequest struct {
	WorkloadID string
	Generation uint64
}

type Provider interface {
	GenerateKey(context.Context, GenerateRequest) (Key, error)
}

type ProviderFunc func(context.Context, GenerateRequest) (Key, error)

func (f ProviderFunc) GenerateKey(ctx context.Context, request GenerateRequest) (Key, error) {
	return f(ctx, request)
}

type OperationMode uint8

const (
	LocalReferenceMode OperationMode = iota + 1
	RemoteSignMode
)

type Key interface {
	crypto.Signer
	Reference() []byte
	Generation() uint64
	OperationMode() OperationMode
	OpaqueWorkloadKey()
}

type key struct {
	crypto.Signer
	reference  []byte
	generation uint64
	mode       OperationMode
}

func NewKey(signer crypto.Signer, reference []byte, generation uint64) Key {
	return NewKeyWithMode(signer, reference, generation, RemoteSignMode)
}

func NewKeyWithMode(signer crypto.Signer, reference []byte, generation uint64, mode OperationMode) Key {
	return &key{
		Signer:     signer,
		reference:  append([]byte(nil), reference...),
		generation: generation,
		mode:       mode,
	}
}

func (k *key) Reference() []byte {
	return append([]byte(nil), k.reference...)
}

func (k *key) Generation() uint64 {
	return k.generation
}

func (k *key) OperationMode() OperationMode {
	return k.mode
}

func (*key) OpaqueWorkloadKey() {}

func IsOpaque(signer crypto.Signer) bool {
	_, ok := signer.(interface{ OpaqueWorkloadKey() })
	return ok
}
