//go:build windows

package cache

import "golang.org/x/sys/windows"

// Windows Chmod only changes the read-only attribute. Protect the DACL instead,
// granting access to the current process user and disabling inherited grants.
func privateDACL(inherit bool) (*windows.ACL, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	flags := ""
	if inherit {
		flags = "OICI"
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;" + flags + ";FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return nil, err
	}
	dacl, _, err := sd.DACL()
	return dacl, err
}

func setPrivateDirPermissions(path string) error {
	dacl, err := privateDACL(true)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	// MAXIMUM_ALLOWED is intentional: SetSecurityInfo then changes only this
	// directory without propagating new grants into existing children. Windows
	// may normalize inherited flags while retaining those children's grants.
	// https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo
	h, err := windows.CreateFile(name, windows.MAXIMUM_ALLOWED,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	return windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}

func setPrivateFilePermissions(path string) error {
	dacl, err := privateDACL(false)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}
