package probe

import (
	"sync"

	"github.com/aaronburt/netscan/internal/config"
)

// KnownTarget is a (layer, address) pair that already has an id, usually read
// from the targets table.
type KnownTarget struct {
	ID      int
	Layer   Layer
	Address string
}

type idKey struct {
	layer Layer
	addr  string
}

// IDAllocator hands out target ids that depend only on (layer, address), never
// on list position, so history stays attached to the host it was recorded for
// however the host lists change.
//
// The default hosts keep the ids older versions gave them. Hosts already
// known from the database keep theirs. Anything else gets the next free id
// from overflowIDBase and keeps it for good once it is persisted.
type IDAllocator struct {
	lock     sync.Mutex
	byKey    map[idKey]int
	used     map[int]bool
	defaults map[idKey]int
	next     int
}

func NewIDAllocator(known []KnownTarget) *IDAllocator {
	a := &IDAllocator{
		byKey:    make(map[idKey]int),
		used:     map[int]bool{GatewayTargetID: true, ISPHopTargetID: true},
		defaults: make(map[idKey]int),
		next:     overflowIDBase,
	}

	def := config.DefaultConfig().Targets
	for i, addr := range def.WANICMP {
		a.defaults[idKey{LayerWANICMP, addr}] = wanICMPIDBase + i
	}
	for i, addr := range def.WANTCP {
		a.defaults[idKey{LayerWANTCP, addr}] = wanTCPIDBase + i
	}
	for i, addr := range def.DNS {
		a.defaults[idKey{LayerDNS, addr}] = dnsIDBase + i
	}
	for i, h := range def.HTTP {
		a.defaults[idKey{LayerHTTP, h.URL}] = httpIDBase + i
	}

	for _, k := range known {
		key := idKey{k.Layer, k.Address}
		if _, dup := a.byKey[key]; dup || a.used[k.ID] {
			continue
		}
		a.byKey[key] = k.ID
		a.used[k.ID] = true
		if k.ID >= a.next {
			a.next = k.ID + 1
		}
	}
	return a
}

// ID returns the id for a host, assigning one the first time it is seen.
// prefBase, when non-zero, is the start of a block of maxPerBase ids to use
// before falling back to the overflow range.
func (a *IDAllocator) ID(layer Layer, addr string, prefBase int) int {
	a.lock.Lock()
	defer a.lock.Unlock()

	key := idKey{layer, addr}
	if id, ok := a.byKey[key]; ok {
		return id
	}

	id := 0
	if d, ok := a.defaults[key]; ok && !a.used[d] {
		id = d
	}
	for i := 0; id == 0 && prefBase != 0 && i < maxPerBase; i++ {
		if !a.used[prefBase+i] {
			id = prefBase + i
		}
	}
	if id == 0 {
		id = a.next
		a.next++
	}

	a.byKey[key] = id
	a.used[id] = true
	return id
}
