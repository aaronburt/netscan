package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Fingerprint returns how profile history stores p: the JSON snapshot of the
// whole profile, and a hash of its settings. The hash leaves out the id, name
// and description, so renaming a profile doesn't change how it polls.
func (p Profile) Fingerprint() (hash, snapshot string) {
	// Profiles hold only plain values, so marshalling them cannot fail.
	full, _ := json.Marshal(p)

	settings := p
	settings.ID, settings.Name, settings.Description = "", "", ""
	plain, _ := json.Marshal(settings)
	sum := sha256.Sum256(plain)

	return hex.EncodeToString(sum[:]), string(full)
}
