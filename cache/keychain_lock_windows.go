//go:build windows

package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func lockKeychain(service, key string) (func(), error) {
	unlockProcess := lockKeychainProcess(service, key)
	base, err := os.UserCacheDir()
	if err != nil {
		unlockProcess()
		return nil, err
	}
	dir := filepath.Join(base, "msauth-go", "keychain-locks")
	if err := ensurePrivateDir(dir); err != nil {
		unlockProcess()
		return nil, err
	}
	h := sha256.Sum256([]byte(service + "\x00" + key))
	f, err := os.OpenFile(filepath.Join(dir, hex.EncodeToString(h[:])+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		unlockProcess()
		return nil, err
	}
	o := new(windows.Overlapped)
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, o); err != nil {
		_ = f.Close()
		unlockProcess()
		return nil, fmt.Errorf("keychain: lock: %w", err)
	}
	return func() { _ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, o); _ = f.Close(); unlockProcess() }, nil
}
