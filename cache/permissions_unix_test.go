//go:build !windows

package cache

import (
	"os"
	"testing"
)

func permissionSnapshot(t *testing.T, path string) string {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().String()
}

func assertPrivateCachePermissions(t *testing.T, dir, key, blob string) {
	t.Helper()
	for path, want := range map[string]os.FileMode{dir: 0o700, key: 0o600, blob: 0o600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Fatalf("%s mode = %o, want %o", path, got, want)
		}
	}
}
