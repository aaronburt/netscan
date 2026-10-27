package updater

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateExecutableForOS(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, magic string) string {
		p := filepath.Join(dir, name)
		buf := make([]byte, 600*1024)
		copy(buf, magic)
		if err := os.WriteFile(p, buf, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	elf := write("elf", "\x7fELF")
	pe := write("pe", "MZ")

	if err := validateExecutableFor(elf, "linux"); err != nil {
		t.Errorf("ELF on linux: %v", err)
	}
	if err := validateExecutableFor(pe, "linux"); err == nil {
		t.Error("PE accepted on linux")
	}
	if err := validateExecutableFor(pe, "windows"); err != nil {
		t.Errorf("PE on windows: %v", err)
	}
	if err := validateExecutableFor(elf, "windows"); err == nil {
		t.Error("ELF accepted on windows")
	}
}
