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

func TestPrivateDirectoryPreservesExistingChildGrants(t *testing.T) {
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
	// Windows preserves access but can turn old inherited ACEs into explicit
	// ACEs when the parent no longer grants them. Compare every grant field,
	// allowing only that INHERITED_ACE metadata normalization.
	if withoutInheritedACEFlag(t, before.String()) != withoutInheritedACEFlag(t, after.String()) {
		t.Fatalf("directory protection changed child grants: %s -> %s", before.String(), after.String())
	}
}

func withoutInheritedACEFlag(t *testing.T, sddl string) string {
	t.Helper()
	parts := strings.Split(sddl, "(")
	for i := 1; i < len(parts); i++ {
		fields := strings.Split(parts[i], ";")
		if len(fields) != 6 {
			t.Fatalf("unexpected ACE format: %s", parts[i])
		}
		fields[1] = strings.ReplaceAll(fields[1], "ID", "")
		parts[i] = strings.Join(fields, ";")
	}
	return strings.Join(parts, "(")
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

func TestNonregularWindowsKeyRetainsItsACL(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, keyFileName)
	if err := os.Mkdir(key, 0o755); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(key, "unrelated")
	if err := os.WriteFile(child, []byte("synthetic"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := map[string]string{}
	for _, path := range []string{key, child} {
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		before[path] = sd.String()
	}
	if err := NewFileStore(dir).Save(t.Context(), "cache", []byte("synthetic")); err == nil {
		t.Fatal("accepted a directory as an encryption key")
	}
	for path, want := range before {
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		if sd.String() != want {
			t.Fatalf("invalid key path ACL changed: %s -> %s", want, sd.String())
		}
	}
}
