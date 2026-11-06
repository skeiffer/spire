package externalstate

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/diskutil"
)

const maxStateBytes = 8 << 20

type Assertion struct {
	Version          int      `json:"version"`
	TrustDomain      string   `json:"trust_domain"`
	Instance         string   `json:"instance"`
	Issuer           string   `json:"issuer"`
	IssuerChecksum   string   `json:"issuer_checksum"`
	KeyManagerDigest string   `json:"key_manager_digest"`
	RetainedRoots    [][]byte `json:"retained_roots"`
}

type ownershipRecord struct {
	Version int    `json:"version"`
	Binding string `json:"binding"`
	DataDir string `json:"data_dir"`
}

type owner struct {
	dir        string
	controlDir string
	binding    string
	fresh      bool
	assertion  Assertion
	locks      []*os.File
	mu         sync.Mutex
	checkpoint checkpoint
	failed     bool
}

func Open(controlDir, dataDir, trustDomain string, configs catalog.PluginConfigs) (_ Owner, err error) {
	if !filepath.IsAbs(controlDir) || !filepath.IsAbs(dataDir) {
		return nil, errors.New("external issuer control directory and data_dir must be absolute")
	}
	controlDir, dataDir = filepath.Clean(controlDir), filepath.Clean(dataDir)
	if within(controlDir, dataDir) || within(dataDir, controlDir) {
		return nil, errors.New("external issuer control directory and data_dir must be independent")
	}
	if err := securePath(controlDir); err != nil {
		return nil, fmt.Errorf("unsafe external issuer control directory: %w", err)
	}
	o := &owner{dir: filepath.Join(dataDir, "external-x509"), controlDir: controlDir}
	defer func() {
		if err != nil {
			_ = o.Close()
		}
	}()
	lock, err := lockFile(filepath.Join(controlDir, "owner.lock"))
	if err != nil {
		return nil, fmt.Errorf("external issuer provisioning state is already owned or inaccessible: %w", err)
	}
	o.locks = append(o.locks, lock)
	if err := ReadJSON(filepath.Join(controlDir, "provision.json"), &o.assertion); err != nil {
		return nil, fmt.Errorf("read external issuer provisioning assertion: %w", err)
	}
	a := o.assertion
	if a.Version != 1 || a.Instance == "" || len(a.Instance) > 256 || a.TrustDomain != trustDomain || a.Issuer == "" || a.KeyManagerDigest == "" {
		return nil, errors.New("external issuer provisioning assertion has an unsupported version or mismatched identity")
	}
	if len(a.RetainedRoots) > 128 {
		return nil, errors.New("retained trust authorization exceeds its resource limit")
	}
	for _, raw := range a.RetainedRoots {
		cert, err := x509.ParseCertificate(raw)
		if err != nil || len(raw) > 64<<10 || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errors.New("retained trust authorization contains an invalid CA certificate")
		}
	}
	var km catalog.PluginConfig
	var kmCount, issuerCount int
	for i := range configs {
		c := &configs[i]
		if !c.IsEnabled() {
			continue
		}
		switch c.Type {
		case "KeyManager":
			kmCount++
			km = *c
		case "X509SVIDIssuer":
			issuerCount++
			if c.Name != a.Issuer || c.Checksum != a.IssuerChecksum || !c.IsExternal() || c.Checksum == "" {
				return nil, errors.New("external issuer plugin identity does not match provisioning assertion")
			}
		}
	}
	if kmCount != 1 || issuerCount != 1 {
		return nil, errors.New("external provisioning requires exactly one KeyManager and one X509SVIDIssuer")
	}
	digest, data, err := KeyManagerDigest(km)
	if err != nil {
		return nil, err
	}
	if digest != a.KeyManagerDigest {
		return nil, errors.New("KeyManager configuration does not match the independently provisioned namespace")
	}
	// Freeze dynamic configuration so catalog configuration cannot read a different namespace.
	for i := range configs {
		if configs[i].Type == "KeyManager" && configs[i].IsEnabled() {
			configs[i].DataSource = catalog.FixedData(data)
		}
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	o.binding = hex.EncodeToString(sum[:])
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, err
	}
	if err := securePath(dataDir); err != nil {
		return nil, err
	}
	lock, err = lockFile(filepath.Join(dataDir, ".external-x509-owner.lock"))
	if err != nil {
		return nil, fmt.Errorf("external issuer data_dir is already owned or inaccessible: %w", err)
	}
	o.locks = append(o.locks, lock)
	record := ownershipRecord{Version: 1, Binding: o.binding, DataDir: dataDir}
	recordPath := filepath.Join(controlDir, "established.json")
	var existing ownershipRecord
	switch err := ReadJSON(recordPath, &existing); {
	case err == nil:
		if existing != record {
			return nil, errors.New("external issuer ownership record does not match provisioning identity or data_dir")
		}
		if err := ReadJSON(filepath.Join(o.dir, "owner.json"), &existing); err != nil || existing != record {
			return nil, errors.New("established external issuer metadata is missing or mismatched; restore matching state before restarting")
		}
	case errors.Is(err, os.ErrNotExist):
		for _, name := range []string{"checkpoint.json", "checkpoint.json.tmp"} {
			if _, err := os.Lstat(filepath.Join(controlDir, name)); !errors.Is(err, os.ErrNotExist) {
				return nil, errors.New("independent checkpoint exists without its ownership record; restore matching state")
			}
		}
		entries, err := os.ReadDir(dataDir)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		for _, entry := range entries {
			if entry.Name() != ".external-x509-owner.lock" {
				return nil, errors.New("first external issuer provisioning requires an empty data_dir")
			}
		}
		if km.Name == "disk" && !km.IsExternal() {
			var config struct {
				KeysPath string `hcl:"keys_path"`
			}
			if err := hcl.Decode(&config, data); err != nil {
				return nil, fmt.Errorf("decode provisioned disk KeyManager configuration: %w", err)
			}
			if !filepath.IsAbs(config.KeysPath) {
				return nil, errors.New("external disk KeyManager keys_path must be absolute")
			}
			if _, err := os.Lstat(config.KeysPath); !errors.Is(err, os.ErrNotExist) {
				return nil, errors.New("first external provisioning requires absent, dedicated disk KeyManager storage")
			}
			if err := securePath(filepath.Dir(config.KeysPath)); err != nil {
				return nil, fmt.Errorf("unsafe dedicated KeyManager directory: %w", err)
			}
		}
		if err := os.MkdirAll(o.dir, 0700); err != nil {
			return nil, err
		}
		if err := WriteJSON(filepath.Join(o.dir, "owner.json"), record); err != nil {
			return nil, err
		}
		if err := WriteJSON(recordPath, record); err != nil {
			return nil, err
		}
		o.fresh = true
	default:
		return nil, fmt.Errorf("load external ownership record: %w", err)
	}
	if err := securePath(o.dir); err != nil {
		return nil, err
	}
	if err := o.loadCheckpoint(); err != nil {
		return nil, err
	}
	return o, nil
}

func KeyManagerDigest(c catalog.PluginConfig) (string, string, error) {
	var data string
	var err error
	if c.DataSource != nil {
		data, err = c.DataSource.Load()
		if err != nil {
			return "", "", err
		}
	}
	raw, err := json.Marshal(struct {
		Name, Path, Checksum, Data string
		Args                       []string
	}{c.Name, c.Path, c.Checksum, data, c.Args})
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), data, nil
}

func (o *owner) StateDir() string { return o.dir }

func (o *owner) Binding() string { return o.binding }

func (o *owner) IsFresh() bool { return o.fresh }

func (o *owner) RetainedRoots() [][]byte {
	roots := slices.Clone(o.assertion.RetainedRoots)
	for i, raw := range roots {
		roots[i] = bytes.Clone(raw)
	}
	return roots
}

func (o *owner) Close() error {
	var errs []error
	for _, lock := range slices.Backward(o.locks) {
		errs = append(errs, lock.Close())
	}
	o.locks = nil
	return errors.Join(errs...)
}

func (o *owner) ActivationVersion() (string, error) {
	var request struct {
		Version          int    `json:"version"`
		Binding          string `json:"binding"`
		AuthorityVersion string `json:"authority_version"`
	}
	if err := ReadJSON(filepath.Join(o.controlDir, "activate.json"), &request); err != nil {
		return "", err
	}
	if request.Version != 1 || request.Binding != o.binding || request.AuthorityVersion == "" || len(request.AuthorityVersion) > 256 {
		return "", errors.New("external activation request has an unsupported version or mismatched provisioning binding")
	}
	return request.AuthorityVersion, nil
}

func ReadJSON(path string, value any) error {
	if _, err := os.Lstat(path + ".tmp"); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("ambiguous pending state write; reconcile the temporary file before restarting")
	}
	if err := securePath(path); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > maxStateBytes {
		return errors.New("state must be a bounded regular file")
	}
	decoder := json.NewDecoder(io.LimitReader(f, maxStateBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("state contains trailing data")
	}
	return nil
}

func WriteJSON(path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(raw) > maxStateBytes {
		return errors.New("external issuer state size limit reached")
	}
	// Refuse to overwrite a leftover file whose commit outcome has not been reconciled.
	if _, err := os.Lstat(path + ".tmp"); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("ambiguous pending state write")
	}
	return writeStateFile(path, bytes.Clone(raw))
}

func writeStateFile(path string, raw []byte) error {
	return diskutil.AtomicWritePrivateFile(path, raw)
}

func within(path, parent string) bool {
	relative, err := filepath.Rel(parent, path)
	return err == nil && (relative == "." || (relative != ".." && !filepath.IsAbs(relative) && !strings.HasPrefix(relative, ".."+string(filepath.Separator))))
}
