package externalstate

type Owner interface {
	StateDir() string
	Binding() string
	IsFresh() bool
	RetainedRoots() [][]byte
	ActivationVersion() (string, error)
	WriteJSON(string, any) error
	WriteFile(string, []byte) error
	Close() error
}
