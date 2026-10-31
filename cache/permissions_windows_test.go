//go:build windows

package cache

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func assertPrivateCachePermissions(t *testing.T, dir, key, blob string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, key, blob} {
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		control, _, err := sd.Control()
		if err != nil {
			t.Fatal(err)
		}
		if control&windows.SE_DACL_PROTECTED == 0 {
			t.Fatalf("%s DACL still inherits grants: %s", path, sd.String())
		}
		dacl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if dacl == nil || dacl.AceCount != 1 {
			t.Fatalf("%s DACL must grant only the current user: %s", path, sd.String())
		}
		flags := ""
		if path == dir {
			flags = "OICI"
		}
		want, err := windows.SecurityDescriptorFromString("D:P(A;" + flags + ";FA;;;" + user.User.Sid.String() + ")")
		if err != nil {
			t.Fatal(err)
		}
		_, wantACE, _ := strings.Cut(want.String(), "(")
		if !strings.HasSuffix(sd.String(), "("+wantACE) {
			t.Fatalf("%s DACL = %s, want %s", path, sd.String(), want.String())
		}
	}
}

func TestPrivateDirectoryDoesNotRewriteExistingChildACL(t *testing.T) {
	dir := t.TempDir()
	child := filepath.Join(dir, "unrelated")
	if err := os.WriteFile(child, []byte("synthetic"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := windows.GetNamedSecurityInfo(child, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	after, err := windows.GetNamedSecurityInfo(child, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if before.String() != after.String() {
		t.Fatalf("directory protection changed child ACL: %s -> %s", before.String(), after.String())
	}
}

func TestFileStoreRepairsExistingWindowsKeyACL(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	if err := store.Save(t.Context(), "cache", []byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, keyFileName)
	original, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	public, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := public.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(key, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	value, err := store.Load(t.Context(), "cache")
	if err != nil || string(value) != "synthetic" {
		t.Fatalf("existing cache unreadable: %q %v", value, err)
	}
	current, err := os.ReadFile(key)
	if err != nil || !bytes.Equal(current, original) {
		t.Fatal("repair rotated or lost the encryption key")
	}
	assertPrivateCachePermissions(t, dir, key, store.(*fileStore).path("cache"))
}
