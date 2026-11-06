package externalstate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type checkpointFile struct {
	Digest  string `json:"digest"`
	Pending string `json:"pending"`
}

type checkpoint struct {
	Version int                       `json:"version"`
	Binding string                    `json:"binding"`
	Files   map[string]checkpointFile `json:"files"`
}

func stateFileName(name string) bool {
	return name == "authorities.json" || name == "token-authorities.json"
}

func (o *owner) loadCheckpoint() error {
	path := filepath.Join(o.controlDir, "checkpoint.json")
	if o.fresh {
		o.checkpoint = checkpoint{Version: 1, Binding: o.binding, Files: make(map[string]checkpointFile)}
		return WriteJSON(path, o.checkpoint)
	}
	if err := ReadJSON(path, &o.checkpoint); err != nil {
		return fmt.Errorf("load independent state checkpoint: %w", err)
	}
	if o.checkpoint.Version != 1 || o.checkpoint.Binding != o.binding || o.checkpoint.Files == nil || len(o.checkpoint.Files) > 2 {
		return errors.New("independent state checkpoint has an unsupported version or mismatched identity")
	}
	changed := false
	for name, record := range o.checkpoint.Files {
		if !stateFileName(name) || !validDigest(record.Digest) || !validDigest(record.Pending) {
			return errors.New("invalid independent state checkpoint")
		}
		actual, err := stateDigest(filepath.Join(o.dir, name))
		if err != nil {
			return err
		}
		switch {
		case actual == record.Digest:
			changed = changed || record.Pending != ""
			record.Pending = ""
		case record.Pending != "" && actual == record.Pending:
			record.Digest, record.Pending = actual, ""
			changed = true
		default:
			return errors.New("external metadata rollback or unprovable restore detected; restore matching independent evidence")
		}
		o.checkpoint.Files[name] = record
	}
	for _, name := range []string{"authorities.json", "token-authorities.json"} {
		if _, ok := o.checkpoint.Files[name]; ok {
			continue
		}
		actual, err := stateDigest(filepath.Join(o.dir, name))
		if err != nil {
			return err
		}
		if actual != "" {
			return errors.New("external metadata has no independent commit attribution")
		}
	}
	if changed {
		return WriteJSON(path, o.checkpoint)
	}
	return nil
}

func (o *owner) WriteJSON(path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return o.WriteFile(path, raw)
}

func (o *owner) WriteFile(path string, raw []byte) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.failed {
		return errors.New("independent state commit failed; restart with reconciled durable state")
	}
	name := filepath.Base(path)
	if filepath.Clean(filepath.Dir(path)) != o.dir || !stateFileName(name) || len(raw) > maxStateBytes || !json.Valid(raw) {
		return errors.New("invalid external metadata write")
	}
	record := o.checkpoint.Files[name]
	actual, err := stateDigest(path)
	if err != nil {
		return err
	}
	if actual != record.Digest || record.Pending != "" {
		o.failed = true
		return errors.New("external metadata no longer matches independent commit evidence")
	}
	sum := sha256.Sum256(raw)
	record.Pending = hex.EncodeToString(sum[:])
	o.checkpoint.Files[name] = record
	checkpointPath := filepath.Join(o.controlDir, "checkpoint.json")
	if err := WriteJSON(checkpointPath, o.checkpoint); err != nil {
		o.failed = true
		return err
	}
	if err := writeStateFile(path, raw); err != nil {
		o.failed = true
		return err
	}
	record.Digest, record.Pending = record.Pending, ""
	o.checkpoint.Files[name] = record
	if err := WriteJSON(checkpointPath, o.checkpoint); err != nil {
		o.failed = true
		return err
	}
	return nil
}

func stateDigest(path string) (string, error) {
	if _, err := os.Lstat(path + ".tmp"); err == nil || !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("ambiguous pending metadata write; reconcile the temporary file")
	}
	if err := securePath(path); errors.Is(err, os.ErrNotExist) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > maxStateBytes {
		return "", errors.New("external metadata must be a bounded regular file")
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, io.LimitReader(f, maxStateBytes+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func validDigest(value string) bool {
	if value == "" {
		return true
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}
