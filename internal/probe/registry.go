package probe

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/aaronburt/netscan/internal/config"
)

// Fixed target ids. Gateway and ISP hop always use these. Other ids come from
// the IDAllocator: the default hosts keep the base+index ids older versions
// gave them, system resolvers prefer the systemDNSIDBase block, and every
// other host gets an id from overflowIDBase up.
const (
	GatewayTargetID = 1
	ISPHopTargetID  = 2

	wanICMPIDBase   = 10
	wanTCPIDBase    = 20
	dnsIDBase       = 30
	systemDNSIDBase = 40
	httpIDBase      = 50
	maxPerBase      = 10
	overflowIDBase  = 1000
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
	ids             *IDAllocator
	dnsQueryName    string
	systemResolvers []string
}

// NewTargetRegistry builds a registry with no id history, as for a new
// database. Use NewTargetRegistryWithIDs when a database may already hold
// targets.
func NewTargetRegistry(p config.Profile) *TargetRegistry {
	return NewTargetRegistryWithIDs(p, NewIDAllocator(nil))
}

func NewTargetRegistryWithIDs(p config.Profile, ids *IDAllocator) *TargetRegistry {
	r := &TargetRegistry{
		allTargets:   make(map[int]Target),
		ids:          ids,
		dnsQueryName: p.Targets.DNSQueryName,
	}

	for _, addr := range p.Targets.WANICMP {
		id := r.ids.ID(LayerWANICMP, addr, 0)
		if _, dup := r.allTargets[id]; dup {
			continue
		}
		t := Target{
			ID:      id,
			Layer:   LayerWANICMP,
			Address: addr,
			Label:   fmt.Sprintf("WAN ICMP (%s)", addr),
		}
		r.wanICMP = append(r.wanICMP, t)
		r.allTargets[id] = t
	}

	for _, addr := range p.Targets.WANTCP {
		id := r.ids.ID(LayerWANTCP, addr, 0)
		if _, dup := r.allTargets[id]; dup {
			continue
		}
		t := Target{
			ID:      id,
			Layer:   LayerWANTCP,
			Address: addr,
			Label:   fmt.Sprintf("WAN TCP (%s)", addr),
		}
		r.wanTCP = append(r.wanTCP, t)
		r.allTargets[id] = t
	}

	for _, addr := range p.Targets.DNS {
		id := r.ids.ID(LayerDNS, addr, 0)
		if _, dup := r.allTargets[id]; dup {
			continue
		}
		t := Target{
			ID:      id,
			Layer:   LayerDNS,
			Address: addr,
			Label:   fmt.Sprintf("DNS (%s)", addr),
		}
		r.dns = append(r.dns, t)
		r.allTargets[id] = t
	}

	for _, h := range p.Targets.HTTP {
		id := r.ids.ID(LayerHTTP, h.URL, 0)
		if _, dup := r.allTargets[id]; dup {
			continue
		}
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

// WithDefaultPort adds port to addr unless it already has one. It handles
// IPv6 literals such as "fec0::1" and "[fec0::1]:53".
func WithDefaultPort(addr, port string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(strings.Trim(addr, "[]"), port)
}

func (r *TargetRegistry) SetGateway(ip net.IP) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if ip == nil || ip.IsUnspecified() || ip.Equal(net.IPv4zero) {
		r.gateway = nil
		delete(r.allTargets, GatewayTargetID)
		return
	}

	t := Target{
		ID:      GatewayTargetID,
		Layer:   LayerGateway,
		Address: ip.String(),
		Label:   fmt.Sprintf("Gateway (%s)", ip.String()),
	}
	r.gateway = &t
	r.allTargets[GatewayTargetID] = t
}

func (r *TargetRegistry) SetISPHop(ip net.IP, ttl byte) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if ip == nil || ip.IsUnspecified() || ip.Equal(net.IPv4zero) {
		r.ispHop = nil
		delete(r.allTargets, ISPHopTargetID)
		return
	}

	t := Target{
		ID:      ISPHopTargetID,
		Layer:   LayerISPHop,
		Address: ip.String(),
		Label:   fmt.Sprintf("ISP Hop (%s)", ip.String()),
		TTL:     ttl,
	}
	r.ispHop = &t
	r.allTargets[ISPHopTargetID] = t
}

func (r *TargetRegistry) UpdateSystemResolvers(resolvers []string) {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.systemResolvers = resolvers

	kept := make([]Target, 0, len(r.dns))
	for _, t := range r.dns {
		if strings.HasPrefix(t.Label, "System DNS") {
			// Drop the old system resolvers so ones that went away don't
			// linger in allTargets.
			delete(r.allTargets, t.ID)
			continue
		}
		kept = append(kept, t)
	}

	seen := make(map[string]bool, len(kept))
	for _, t := range kept {
		seen[WithDefaultPort(t.Address, "53")] = true
	}

	for _, s := range resolvers {
		key := WithDefaultPort(s, "53")
		if seen[key] {
			continue
		}
		seen[key] = true

		id := r.ids.ID(LayerDNS, s, systemDNSIDBase)
		t := Target{
			ID:      id,
			Layer:   LayerDNS,
			Address: s,
			Label:   fmt.Sprintf("System DNS (%s)", s),
		}
		kept = append(kept, t)
		r.allTargets[id] = t
	}

	r.dns = kept
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
