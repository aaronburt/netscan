package config

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestDataDirResolution(t *testing.T) {
	home := func() (string, error) { return "/home/u", nil }
	noHome := func() (string, error) { return "", errors.New("no home") }
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}

	cases := []struct {
		name string
		goos string
		env  map[string]string
		home func() (string, error)
		want string
	}{
		{"override wins on linux", "linux", map[string]string{"NETSCAN_DATA_DIR": "/x", "STATE_DIRECTORY": "/s", "XDG_DATA_HOME": "/d"}, home, "/x"},
		{"state directory", "linux", map[string]string{"STATE_DIRECTORY": "/var/lib/netscan", "XDG_DATA_HOME": "/d"}, home, "/var/lib/netscan"},
		{"state directory list", "linux", map[string]string{"STATE_DIRECTORY": "/a:/b"}, home, "/a"},
		{"xdg data home", "linux", map[string]string{"XDG_DATA_HOME": "/d"}, home, filepath.Join("/d", "netscan")},
		{"home fallback", "linux", nil, home, filepath.Join("/home/u", ".local", "share", "netscan")},
		{"no home", "linux", nil, noHome, ".netscan"},
		{"windows ignores linux vars", "windows", map[string]string{"STATE_DIRECTORY": "/s", "LOCALAPPDATA": `C:\L`}, home, filepath.Join(`C:\L`, "NetScan")},
		{"windows home fallback", "windows", nil, home, filepath.Join("/home/u", "AppData", "Local", "NetScan")},
		{"windows no home", "windows", nil, noHome, ".netscan"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := dataDir(c.goos, env(c.env), c.home); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}
