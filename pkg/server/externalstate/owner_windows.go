//go:build windows

package externalstate

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
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
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink is not allowed at %q", current)
		}
		sd, err := windows.GetNamedSecurityInfo(current, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return err
		}
		owner, _, err := sd.Owner()
		if err != nil {
			return err
		}
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			return err
		}
		system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
		if err != nil {
			return err
		}
		admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
		if err != nil {
			return err
		}
		installer, _, _, err := windows.LookupSID("", `NT SERVICE\TrustedInstaller`)
		if err != nil {
			return err
		}
		ownerRights, err := windows.StringToSid("S-1-3-4")
		if err != nil {
			return err
		}
		trusted := func(sid *windows.SID) bool {
			return sid.Equals(user.User.Sid) || sid.Equals(system) || sid.Equals(admins) || sid.Equals(installer)
		}
		if !trusted(owner) {
			return fmt.Errorf("untrusted owner for %q", current)
		}
		dacl, _, err := sd.DACL()
		if err != nil || dacl == nil {
			return fmt.Errorf("missing protected DACL for %q", current)
		}
		for i := uint32(0); i < uint32(dacl.AceCount); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(dacl, i, &ace); err != nil {
				return err
			}
			if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
				continue
			}
			if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
				return fmt.Errorf("unsupported access-control entry at %q", current)
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			const fileDeleteChild = 0x40
			mutation := windows.ACCESS_MASK(windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.DELETE | fileDeleteChild)
			if current == path {
				mutation |= windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA
			}
			if ace.Mask&mutation != 0 && !trusted(sid) && !sid.Equals(ownerRights) {
				return fmt.Errorf("untrusted write access to %q", current)
			}
		}
		if parent := filepath.Dir(current); parent == current {
			return nil
		}
	}
}

func lockFile(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(handle), path)
	if err := securePath(path); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
