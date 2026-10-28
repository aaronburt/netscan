package app

import "testing"

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestShouldRunHeadless(t *testing.T) {
	cases := []struct {
		name string
		goos string
		env  map[string]string
		want bool
	}{
		{"systemd with display", "linux", map[string]string{"INVOCATION_ID": "abc", "DISPLAY": ":0"}, true},
		{"linux no display", "linux", nil, true},
		{"linux x11", "linux", map[string]string{"DISPLAY": ":0"}, false},
		{"linux wayland", "linux", map[string]string{"WAYLAND_DISPLAY": "wayland-0"}, false},
		{"windows no display vars", "windows", nil, false},
	}
	for _, c := range cases {
		if got := ShouldRunHeadless(c.goos, env(c.env)); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestUnderSystemd(t *testing.T) {
	if UnderSystemd(env(nil)) {
		t.Error("no INVOCATION_ID should not be a service")
	}
	if !UnderSystemd(env(map[string]string{"INVOCATION_ID": "x"})) {
		t.Error("INVOCATION_ID should mark a service")
	}
}

func TestInContainer(t *testing.T) {
	none := func(string) bool { return false }
	dockerenv := func(p string) bool { return p == "/.dockerenv" }
	podman := func(p string) bool { return p == "/run/.containerenv" }
	cases := []struct {
		name   string
		env    map[string]string
		exists func(string) bool
		want   bool
	}{
		{"image sets the variable", map[string]string{"NETSCAN_CONTAINER": "1"}, none, true},
		{"variable turns detection off", map[string]string{"NETSCAN_CONTAINER": "0"}, dockerenv, false},
		{"docker marker file", nil, dockerenv, true},
		{"podman marker file", nil, podman, true},
		{"bare host", nil, none, false},
	}
	for _, c := range cases {
		if got := InContainer(env(c.env), c.exists); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
