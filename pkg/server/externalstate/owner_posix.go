//go:build !windows

package externalstate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func securePath(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (int64(stat.Uid) != int64(os.Geteuid()) && stat.Uid != 0) {
			return fmt.Errorf("untrusted owner for %q", current)
		}
		if info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 && !(info.IsDir() && info.Mode()&os.ModeSticky != 0 && current != path) {
			return fmt.Errorf("unsafe permissions or symlink at %q", current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}

func lockFile(path string) (*os.File, error) {
	if _, err := os.Lstat(path); err == nil {
		if err := securePath(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
