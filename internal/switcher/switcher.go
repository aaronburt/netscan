// Package switcher changes the polling profile of a running monitor.
package switcher

import (
	"fmt"
	"strings"
	"sync"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/probe"
)

// Detector is told about a switch first, so it stops judging results from
// the old plan.
type Detector interface {
	Apply(p config.Profile)
}

// Scheduler plans from the registry it is given, so it is switched last.
type Scheduler interface {
	Apply(p config.Profile, reg *probe.TargetRegistry)
}

// Switcher applies a profile to every component that depends on it.
type Switcher struct {
	mu       sync.Mutex
	current  config.Profile
	reg      *probe.TargetRegistry
	sched    Scheduler
	det      Detector
	onTarget func(probe.Target)
	onChange func(config.Profile)
}

// New returns a Switcher for components already running on current. onTarget
// is called for every target after a switch, so new hosts get stored; onChange
// is called once the switch is complete, and may be nil.
func New(current config.Profile, reg *probe.TargetRegistry, sched Scheduler, det Detector, onTarget func(probe.Target), onChange func(config.Profile)) *Switcher {
	return &Switcher{current: current, reg: reg, sched: sched, det: det, onTarget: onTarget, onChange: onChange}
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

	s.det.Apply(p)
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
