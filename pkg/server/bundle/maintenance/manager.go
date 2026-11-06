package maintenance

import "context"

type Manager interface {
	BundleUpdated()
	Initialize(context.Context) error
	Run(context.Context) error
}
