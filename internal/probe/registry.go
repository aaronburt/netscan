package probe

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/aaronburt/netscan/internal/config"
)

type TargetRegistry struct {
	lock            sync.RWMutex
	gateway         *Target
	ispHop          *Target
	wanICMP         []Target
	wanTCP          []Target
	dns             []Target
	http            []Target
	allTargets      map[int]Target
	nextID          int
	dnsQueryName    string
	systemResolvers []string
}

func NewTargetRegistry(cfg config.Config) *TargetRegistry {
	r := &TargetRegistry{
		allTargets:   make(map[int]Target),
		nextID:       100,
		dnsQueryName: cfg.Targets.DNSQueryName,
	}

	for i, addr := range cfg.Targets.WANICMP {
		id := 10 + i
		t := Target{
			ID:      id,
			Layer:   LayerWANICMP,
			Address: addr,
			Label:   fmt.Sprintf("WAN ICMP (%s)", addr),
		}
		r.wanICMP = append(r.wanICMP, t)
		r.allTargets[id] = t
	}

	for i, addr := range cfg.Targets.WANTCP {
		id := 20 + i
		t := Target{
			ID:      id,
			Layer:   LayerWANTCP,
			Address: addr,
			Label:   fmt.Sprintf("WAN TCP (%s)", addr),
		}
		r.wanTCP = append(r.wanTCP, t)
		r.allTargets[id] = t
	}

	for i, addr := range cfg.Targets.DNS {
		id := 30 + i
		t := Target{
			ID:      id,
			Layer:   LayerDNS,
			Address: addr,
			Label:   fmt.Sprintf("DNS (%s)", addr),
		}
		r.dns = append(r.dns, t)
		r.allTargets[id] = t
	}

	for i, h := range cfg.Targets.HTTP {
		id := 50 + i
		label := h.URL
		if len(label) > 30 {
			label = label[:30] + "..."
		}
		t := Target{
			ID:         id,
			Layer:      LayerHTTP,
			Address:    h.URL,
			Label:      fmt.Sprintf("HTTP (%s)", label),
			Expected:   h.Status,
			BodyPrefix: h.BodyPrefix,
		}
		r.http = append(r.http, t)
		r.allTargets[id] = t
	}

	return r
}

func (r *TargetRegistry) SetGateway(ip net.IP) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if ip == nil || ip.IsUnspecified() || ip.Equal(net.IPv4zero) {
		r.gateway = nil
		delete(r.allTargets, 1)
		return
	}

	t := Target{
		ID:      1,
		Layer:   LayerGateway,
		Address: ip.String(),
		Label:   fmt.Sprintf("Gateway (%s)", ip.String()),
	}
	r.gateway = &t
	r.allTargets[1] = t
}

func (r *TargetRegistry) SetISPHop(ip net.IP, ttl byte) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if ip == nil || ip.IsUnspecified() || ip.Equal(net.IPv4zero) {
		r.ispHop = nil
		delete(r.allTargets, 2)
		return
	}

	t := Target{
		ID:      2,
		Layer:   LayerISPHop,
		Address: ip.String(),
		Label:   fmt.Sprintf("ISP Hop (%s)", ip.String()),
		TTL:     ttl,
	}
	r.ispHop = &t
	r.allTargets[2] = t
}

func (r *TargetRegistry) UpdateSystemResolvers(resolvers []string) {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.systemResolvers = resolvers

	existingDNS := make([]Target, 0)
	for _, t := range r.dns {
		if !strings.HasPrefix(t.Label, "System DNS") {
			existingDNS = append(existingDNS, t)
		}
	}

	sysID := 40
	for _, s := range resolvers {
		isDup := false
		for _, ex := range existingDNS {
			exAddr := ex.Address
			if !strings.Contains(exAddr, ":") {
				exAddr += ":53"
			}
			sAddr := s
			if !strings.Contains(sAddr, ":") {
				sAddr += ":53"
			}
			if exAddr == sAddr {
				isDup = true
				break
			}
		}
		if isDup {
			continue
		}

		t := Target{
			ID:      sysID,
			Layer:   LayerDNS,
			Address: s,
			Label:   fmt.Sprintf("System DNS (%s)", s),
		}
		existingDNS = append(existingDNS, t)
		r.allTargets[sysID] = t
		sysID++
	}

	r.dns = existingDNS
}

func (r *TargetRegistry) GetGateway() *Target {
	r.lock.RLock()
	defer r.lock.RUnlock()
	return r.gateway
}

func (r *TargetRegistry) GetISPHop() *Target {
	r.lock.RLock()
	defer r.lock.RUnlock()
	return r.ispHop
}

func (r *TargetRegistry) GetWANICMP() []Target {
	r.lock.RLock()
	defer r.lock.RUnlock()
	res := make([]Target, len(r.wanICMP))
	copy(res, r.wanICMP)
	return res
}

func (r *TargetRegistry) GetWANTCP() []Target {
	r.lock.RLock()
	defer r.lock.RUnlock()
	res := make([]Target, len(r.wanTCP))
	copy(res, r.wanTCP)
	return res
}

func (r *TargetRegistry) GetDNS() []Target {
	r.lock.RLock()
	defer r.lock.RUnlock()
	res := make([]Target, len(r.dns))
	copy(res, r.dns)
	return res
}

func (r *TargetRegistry) GetHTTP() []Target {
	r.lock.RLock()
	defer r.lock.RUnlock()
	res := make([]Target, len(r.http))
	copy(res, r.http)
	return res
}

func (r *TargetRegistry) GetAllTargets() []Target {
	r.lock.RLock()
	defer r.lock.RUnlock()
	res := make([]Target, 0, len(r.allTargets))
	for _, t := range r.allTargets {
		res = append(res, t)
	}
	return res
}

func (r *TargetRegistry) GetDNSQueryName() string {
	r.lock.RLock()
	defer r.lock.RUnlock()
	return r.dnsQueryName
}
