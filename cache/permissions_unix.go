//go:build !windows

package cache

import "os"

func setPrivateDirPermissions(path string) error  { return os.Chmod(path, 0o700) }
func setPrivateFilePermissions(path string) error { return os.Chmod(path, 0o600) }
