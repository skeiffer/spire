package x509svidissuer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"github.com/spiffe/spire/pkg/common/diskutil"
)

const maxStateSize = 8 << 20

type authorityState struct {
	Format  int                    `json:"format"`
	Active  string                 `json:"active"`
	Records []authorityStateRecord `json:"records"`
}

type authorityStateRecord struct {
	Version    string               `json:"version"`
	Paths      []authorityStatePath `json:"paths"`
	PreparedAt time.Time            `json:"prepared_at"`
	Committed  bool                 `json:"committed"`
	Retired    bool                 `json:"retired"`
}

type authorityStatePath struct {
	Root          []byte   `json:"root"`
	Intermediates [][]byte `json:"intermediates,omitempty"`
}

func (h *Host) load() error {
	file, err := os.Open(h.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return diskutil.CreateDataDirectory(filepath.Dir(h.statePath()))
	}
	if err != nil {
		return fmt.Errorf("open external authority metadata: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxStateSize+1))
	if err != nil {
		return fmt.Errorf("read external authority metadata: %w", err)
	}
	if len(data) > maxStateSize {
		return errors.New("external authority metadata exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state authorityState
	if err := decoder.Decode(&state); err != nil {
		return fmt.Errorf("decode external authority metadata: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("external authority metadata contains trailing data")
	}
	if state.Format != 1 || len(state.Records) == 0 || len(state.Records) > maxHistory {
		return errors.New("unsupported external authority metadata format or history size")
	}
	store := NewAuthorityStore()
	for _, record := range state.Records {
		if record.PreparedAt.IsZero() || store.records[record.Version] != nil {
			return errors.New("external authority metadata has missing preparation time or duplicate version")
		}
		in := &issuerv1.AuthoritySnapshot{AuthorityVersion: record.Version}
		for _, path := range record.Paths {
			in.AuthorityChains = append(in.AuthorityChains, &issuerv1.AuthorityChain{
				Root: path.Root, Intermediates: path.Intermediates,
			})
		}
		snapshot, err := SnapshotFromProto(in)
		if err != nil {
			return fmt.Errorf("validate external authority metadata: %w", err)
		}
		if err := store.publish(snapshot, record.PreparedAt); err != nil {
			return err
		}
		entry := store.records[record.Version]
		entry.committed, entry.retired = record.Committed, record.Retired
		if entry.retired && !entry.committed {
			return errors.New("external authority metadata retires an uncommitted version")
		}
	}
	if state.Active != "" {
		record := store.records[state.Active]
		if record == nil || !record.committed || record.retired {
			return errors.New("external authority metadata has an invalid active version")
		}
	}
	store.active = state.Active
	h.store = store
	return nil
}

func (h *Host) saveLocked() error {
	state := authorityState{Format: 1, Active: h.store.active}
	for version, record := range h.store.records {
		out := authorityStateRecord{
			Version: version, PreparedAt: record.preparedAt,
			Committed: record.committed, Retired: record.retired,
		}
		for _, path := range record.snapshot.Paths {
			p := authorityStatePath{Root: path.Root.Raw}
			for _, cert := range path.Intermediates {
				p.Intermediates = append(p.Intermediates, cert.Raw)
			}
			out.Paths = append(out.Paths, p)
		}
		state.Records = append(state.Records, out)
	}
	sort.Slice(state.Records, func(i, j int) bool { return state.Records[i].Version < state.Records[j].Version })
	data, err := json.Marshal(state)
	if err == nil && len(data) > maxStateSize {
		err = errors.New("external authority metadata exceeds size limit")
	}
	if err == nil {
		err = diskutil.AtomicWritePrivateFile(h.statePath(), data)
	}
	if err != nil {
		h.fatal = fmt.Errorf("persist external authority metadata (restore writable, intact server data before restarting): %w", err)
		h.live = false
		return h.fatal
	}
	return nil
}
