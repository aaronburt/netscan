// Package switcher changes the polling profile of a running monitor.
package switcher

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/probe"
)

// Detector is told about a switch first, so it stops judging results from
// the old plan. profileID is the history row the new plan is recorded under.
type Detector interface {
	Apply(p config.Profile, profileID int64)
}

// Scheduler plans from the registry it is given, so it is switched last.
type Scheduler interface {
	Apply(p config.Profile, reg *probe.TargetRegistry)
}

// History records which profile is in force and from when. It is called once
// a switch is accepted, before the components change, so that the id it returns
// is in place before the detector starts stamping events with it.
type History interface {
	Switch(p config.Profile, at time.Time) int64
}

// Switcher applies a profile to every component that depends on it.
type Switcher struct {
	mu       sync.Mutex
	current  config.Profile
	reg      *probe.TargetRegistry
	sched    Scheduler
	det      Detector
	history  History
	onTarget func(probe.Target)
	onChange func(config.Profile)
}

// New returns a Switcher for components already running on current. history
// may be nil, in which case switches are not recorded. onTarget is called for
// every target after a switch, so new hosts get stored; onChange is called once
// the switch is complete, and may be nil.
func New(current config.Profile, reg *probe.TargetRegistry, sched Scheduler, det Detector, history History, onTarget func(probe.Target), onChange func(config.Profile)) *Switcher {
	return &Switcher{current: current, reg: reg, sched: sched, det: det, history: history, onTarget: onTarget, onChange: onChange}
}

// Current returns the profile in force.
func (s *Switcher) Current() config.Profile {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current.Clone()
}

// Apply switches to p. A profile with errors is refused and nothing changes.
// Limit warnings don't stop a switch; whoever asks for it decides whether the
// user has overridden them.
func (s *Switcher) Apply(p config.Profile) error {
	p = p.Clone()
	p.Normalize()
	if c := p.Validate(); len(c.Errors) > 0 {
		msgs := make([]string, len(c.Errors))
		for i, e := range c.Errors {
			msgs[i] = e.Field + " " + e.Message
		}
		return fmt.Errorf("profile %q is invalid: %s", p.ID, strings.Join(msgs, "; "))
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var profileID int64
	if s.history != nil {
		profileID = s.history.Switch(p, time.Now().UTC())
	}
	s.det.Apply(p, profileID)
	targets := s.reg.Reconfigure(p)
	if s.onTarget != nil {
		for _, t := range targets {
			s.onTarget(t)
		}
	}
	s.sched.Apply(p, s.reg)
	s.current = p
	if s.onChange != nil {
		s.onChange(p)
	}
	return nil
}
