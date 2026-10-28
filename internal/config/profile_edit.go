package config

import (
	"fmt"
	"strconv"
	"strings"
)

// apiRouteIDs are the path segments the profiles API uses for its own routes,
// so a custom profile can't take one of them as its id.
var apiRouteIDs = map[string]bool{"validate": true, "test-hosts": true, "reload": true}

// CheckCandidate runs every rule a custom profile must pass before it is saved:
// its own rules and limits (see Validate), then whether its id is free.
// replacing is the id of the custom profile being edited, or "" for a new one.
// It expects a normalized profile.
func (c Config) CheckCandidate(p Profile, replacing string) Check {
	chk := p.Validate()
	switch {
	case IsReservedProfileID(p.ID) || apiRouteIDs[p.ID]:
		chk.Errors = append(chk.Errors, Issue{"id", "is reserved"})
	case p.ID != replacing && c.hasCustom(p.ID):
		chk.Errors = append(chk.Errors, Issue{"id", "is already used by another profile"})
	}
	if replacing == "" && len(c.Profiles) >= LimitCustomProfiles {
		chk.Warnings = append(chk.Warnings, Issue{"profiles", fmt.Sprintf("%d custom profiles; more than %d is not recommended", len(c.Profiles)+1, LimitCustomProfiles)})
	}
	return chk
}

// NewProfileID derives an id for a new profile from its name. The id is kept
// clear of the built-in and API ids and of the ids already in use.
func (c Config) NewProfileID(name string) string {
	base := slugProfileID(name)
	id := base
	for n := 2; c.idTaken(id); n++ {
		suffix := "-" + strconv.Itoa(n)
		stem := base
		if limit := 32 - len(suffix); len(stem) > limit {
			stem = strings.TrimRight(stem[:limit], "-")
		}
		id = stem + suffix
	}
	return id
}

func (c Config) idTaken(id string) bool {
	return IsReservedProfileID(id) || apiRouteIDs[id] || c.hasCustom(id)
}

func (c Config) hasCustom(id string) bool {
	for _, p := range c.Profiles {
		if p.ID == id {
			return true
		}
	}
	return false
}

// slugProfileID turns a name into lower-case words joined by dashes, which
// Validate accepts as an id. A name with no letters or digits becomes "profile".
func slugProfileID(name string) string {
	var b strings.Builder
	gap := false
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			if gap && b.Len() > 0 {
				b.WriteByte('-')
			}
			b.WriteRune(r)
			gap = false
		} else {
			gap = true
		}
	}
	slug := b.String()
	if len(slug) > 32 {
		slug = strings.TrimRight(slug[:32], "-")
	}
	if slug == "" {
		return "profile"
	}
	return slug
}
