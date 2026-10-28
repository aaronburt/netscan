package switcher

import (
	"testing"
	"time"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/probe"
)

type fakeSched struct {
	order *[]string
	got   config.Profile
	reg   *probe.TargetRegistry
}

func (f *fakeSched) Apply(p config.Profile, reg *probe.TargetRegistry) {
	*f.order = append(*f.order, "scheduler")
	f.got, f.reg = p, reg
}

type fakeDet struct {
	order *[]string
	got   config.Profile
	id    int64
}

func (f *fakeDet) Apply(p config.Profile, profileID int64) {
	*f.order = append(*f.order, "detector")
	f.got, f.id = p, profileID
}

type fakeHistory struct {
	order    *[]string
	switched []string
	lastID   int64
}

func (f *fakeHistory) Switch(p config.Profile, _ time.Time) int64 {
	*f.order = append(*f.order, "history")
	f.switched = append(f.switched, p.ID)
	f.lastID++
	return f.lastID
}

func TestApplySwitchesEverything(t *testing.T) {
	std := config.Standard()
	alloc := probe.NewIDAllocator(nil)
	reg := probe.NewTargetRegistryWithIDs(std, alloc)
	var order []string
	sched, det := &fakeSched{order: &order}, &fakeDet{order: &order}
	hist := &fakeHistory{order: &order}
	var stored []probe.Target
	var changed []string
	sw := New(std, reg, sched, det, hist,
		func(t probe.Target) { stored = append(stored, t) },
		func(p config.Profile) { changed = append(changed, p.ID) })

	custom := config.Standard()
	custom.ID, custom.Name, custom.BuiltIn = "home", "Home", false
	custom.Targets.WANTCP = []string{"1.1.1.1:443", "192.0.2.10:443"}
	if err := sw.Apply(custom); err != nil {
		t.Fatal(err)
	}

	if det.got.ID != "home" || sched.got.ID != "home" || sched.reg != reg {
		t.Fatalf("components not switched: det=%s sched=%s", det.got.ID, sched.got.ID)
	}
	if det.id != 1 {
		t.Fatalf("detector got profile id %d, want the one history returned (1)", det.id)
	}
	if len(order) != 3 || order[0] != "history" || order[1] != "detector" {
		t.Fatalf("order = %v, want history recorded, then the detector cleared before the scheduler plans", order)
	}
	if len(reg.GetWANTCP()) != 2 || reg.GetWANTCP()[1].Address != "192.0.2.10:443" {
		t.Fatalf("registry not reconfigured: %+v", reg.GetWANTCP())
	}
	// The shared host keeps its id; the new host gets an overflow id.
	if reg.GetWANTCP()[0].ID != 20 || reg.GetWANTCP()[1].ID < 1000 {
		t.Fatalf("ids: %d, %d", reg.GetWANTCP()[0].ID, reg.GetWANTCP()[1].ID)
	}
	if len(stored) != len(reg.GetAllTargets()) {
		t.Fatalf("stored %d targets, registry has %d", len(stored), len(reg.GetAllTargets()))
	}
	if len(changed) != 1 || changed[0] != "home" || sw.Current().ID != "home" {
		t.Fatalf("changed=%v current=%s", changed, sw.Current().ID)
	}
}

func TestApplyRefusesInvalidProfile(t *testing.T) {
	std := config.Standard()
	reg := probe.NewTargetRegistry(std)
	var order []string
	sched, det := &fakeSched{order: &order}, &fakeDet{order: &order}
	hist := &fakeHistory{order: &order}
	sw := New(std, reg, sched, det, hist, nil, nil)

	bad := config.Standard()
	bad.ID, bad.Mode = "bad", "sideways"
	if err := sw.Apply(bad); err == nil {
		t.Fatal("expected an error for an invalid mode")
	}
	if len(order) != 0 || len(hist.switched) != 0 || sw.Current().ID != config.ProfileStandard {
		t.Fatalf("an invalid profile changed state: order=%v current=%s", order, sw.Current().ID)
	}
}

func TestApplyWithoutHistoryUsesNoProfileID(t *testing.T) {
	std := config.Standard()
	reg := probe.NewTargetRegistry(std)
	var order []string
	det := &fakeDet{order: &order}
	sw := New(std, reg, &fakeSched{order: &order}, det, nil, nil, nil)

	if err := sw.Apply(config.Aggressive()); err != nil {
		t.Fatal(err)
	}
	if det.got.ID != config.ProfileAggressive || det.id != 0 {
		t.Fatalf("detector got %s with profile id %d, want aggressive with 0", det.got.ID, det.id)
	}
}
