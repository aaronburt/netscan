package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/probe"
)

// Without echo requests a ping says nothing about the network, so the ping
// layers must not be probed at all. Probing them would report every ping as
// failed and mark the gateway down.
func TestPingLayersNotProbedWithoutICMP(t *testing.T) {
	saved := icmpUnavailable
	icmpUnavailable = func() error { return errors.New("no ping sockets") }
	t.Cleanup(func() { icmpUnavailable = saved })

	prof := config.Standard()
	prof.Targets.WANICMP = []string{"127.0.0.1"}
	reg := probe.NewTargetRegistry(prof)
	outCh := make(chan probe.ProbeResult, 10)
	s := NewScheduler(prof, reg, outCh, "test", nil)

	s.run(context.Background(), reg.GetWANICMP()[0], false, false)

	select {
	case res := <-outCh:
		t.Fatalf("expected no ping result without ICMP, got %+v", res)
	case <-time.After(50 * time.Millisecond):
	}
}
