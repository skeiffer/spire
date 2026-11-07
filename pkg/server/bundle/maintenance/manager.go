package maintenance

import "context"

type Manager interface {
	BundleUpdated()
	Updates() <-chan struct{}
	Initialize(context.Context) error
	NotifyBundleUpdated(context.Context) error
	PruneBundle(context.Context) error
	Run(context.Context) error
}
