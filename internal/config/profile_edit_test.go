package config_test

import (
	"strings"
	"testing"

	"github.com/aaronburt/netscan/internal/config"
)

func hasIssue(issues []config.Issue, field string) bool {
	for _, i := range issues {
		if i.Field == field {
			return true
		}
	}
	return false
}

func TestNewProfileID(t *testing.T) {
	c := config.Config{Profiles: []config.Profile{customProfile("standard-2")}}
	tests := map[string]string{
		"Office Wi-Fi":           "office-wi-fi",
		"  Lots!!  of   spaces ": "lots-of-spaces",
		"":                       "profile",
		"!!!":                    "profile",
		"Standard":               "standard-3",
		"Lax":                    "lax-2",
		"Reload":                 "reload-2",
	}
	for name, want := range tests {
		if got := c.NewProfileID(name); got != want {
			t.Errorf("NewProfileID(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestNewProfileIDFitsTheIDRules(t *testing.T) {
	long := strings.Repeat("A very long profile name ", 4)
	first := config.Config{}.NewProfileID(long)
	c := config.Config{Profiles: []config.Profile{customProfile(first)}}
	second := c.NewProfileID(long)

	if first == second || !strings.HasSuffix(second, "-2") {
		t.Fatalf("second id %q should take a suffix after %q", second, first)
	}
	for _, id := range []string{first, second} {
		if len(id) > 32 || strings.HasSuffix(id, "-") {
			t.Fatalf("id %q is not a valid length or shape", id)
		}
		if hasIssue(customProfile(id).Validate().Errors, "id") {
			t.Fatalf("id %q fails Validate", id)
		}
	}
}

func TestCheckCandidateIDs(t *testing.T) {
	c := config.Config{Profiles: []config.Profile{customProfile("mine")}}

	for _, id := range []string{"standard", "aggressive", "lax", "validate", "test-hosts", "reload", "history"} {
		chk := c.CheckCandidate(customProfile(id), "")
		if !hasIssue(chk.Errors, "id") {
			t.Errorf("id %q should be reserved", id)
		}
	}

	if chk := c.CheckCandidate(customProfile("mine"), ""); !hasIssue(chk.Errors, "id") {
		t.Error("a new profile may not reuse a taken id")
	}
	if chk := c.CheckCandidate(customProfile("mine"), "mine"); hasIssue(chk.Errors, "id") {
		t.Errorf("editing a profile keeps its own id: %v", chk.Errors)
	}
	if chk := c.CheckCandidate(customProfile("fresh"), ""); len(chk.Errors) != 0 || len(chk.Warnings) != 0 {
		t.Errorf("a valid new profile was refused: %v %v", chk.Errors, chk.Warnings)
	}
}

func TestCheckCandidateCustomProfileCount(t *testing.T) {
	var c config.Config
	for i := 0; i < config.LimitCustomProfiles; i++ {
		c.Profiles = append(c.Profiles, customProfile("p"+string(rune('a'+i))))
	}
	if chk := c.CheckCandidate(customProfile("extra"), ""); !hasIssue(chk.Warnings, "profiles") {
		t.Error("a 17th custom profile should warn")
	}
	if chk := c.CheckCandidate(customProfile("pa"), "pa"); hasIssue(chk.Warnings, "profiles") {
		t.Error("editing an existing profile should not count as a new one")
	}
}
