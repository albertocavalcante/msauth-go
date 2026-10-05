//go:build !windows

package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// lockKeychain serializes cooperating processes before they inspect or publish
// keyring entries. The lock file contains no credentials.
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
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		unlockProcess()
		return nil, fmt.Errorf("keychain: lock: %w", err)
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close(); unlockProcess() }, nil
}
