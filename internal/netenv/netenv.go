package netenv

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/aaronburt/netscan/internal/platform"
	"github.com/aaronburt/netscan/internal/probe"
)

type SystemEventKind string

const (
	SysEventGatewayChange SystemEventKind = "GATEWAY_CHANGE"
	SysEventISPHopChange  SystemEventKind = "ISP_HOP_CHANGE"
	SysEventNetworkChange SystemEventKind = "NETWORK_CHANGE"
	SysEventClockChange   SystemEventKind = "CLOCK_CHANGE"
	SysEventSuspend       SystemEventKind = "SUSPEND"
	SysEventResume        SystemEventKind = "RESUME"
	SysEventRebaseline    SystemEventKind = "REBASELINE"
	SysEventDropped       SystemEventKind = "DROPPED"
	SysEventDiskPressure  SystemEventKind = "DISK_PRESSURE"
)

type SystemEvent struct {
	ID        int64           `json:"id"`
	Timestamp int64           `json:"ts_ms"`
	Kind      SystemEventKind `json:"kind"`
	Detail    string          `json:"detail"`
}

type NetEnv struct {
	registry   *probe.TargetRegistry
	sysEventCh chan SystemEvent

	lock        sync.RWMutex
	currentInfo platform.NetworkInfo
	ispHopIP    net.IP
	ispHopTTL   byte
	fingerprint string
	networkID   int64
	ssid        string
}

func NewNetEnv(registry *probe.TargetRegistry, sysEventCh chan SystemEvent) *NetEnv {
	return &NetEnv{
		registry:   registry,
		sysEventCh: sysEventCh,
	}
}

func (n *NetEnv) Run(ctx context.Context) error {
	n.Refresh(ctx)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	ispTicker := time.NewTicker(1 * time.Hour)
	defer ispTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			n.checkGatewayChange(ctx)
		case <-ispTicker.C:
			n.discoverISPHop(ctx)
		}
	}
}

func (n *NetEnv) Refresh(ctx context.Context) {
	info, err := platform.DiscoverNetworkInfo()
	if err == nil {
		n.applyNetworkInfo(info)
	}
	n.discoverISPHop(ctx)
}

func (n *NetEnv) checkGatewayChange(ctx context.Context) {
	info, err := platform.DiscoverNetworkInfo()
	if err != nil {
		return
	}

	n.lock.RLock()
	oldGW := n.currentInfo.GatewayIP
	n.lock.RUnlock()

	if !info.GatewayIP.Equal(oldGW) {
		n.applyNetworkInfo(info)
		n.emitSystemEvent(SysEventGatewayChange, fmt.Sprintf("gateway changed from %v to %v", oldGW, info.GatewayIP))
		n.discoverISPHop(ctx)
	}
}

func (n *NetEnv) applyNetworkInfo(info platform.NetworkInfo) {
	n.lock.Lock()
	defer n.lock.Unlock()

	n.currentInfo = info
	n.registry.SetGateway(info.GatewayIP)
	n.registry.UpdateSystemResolvers(info.SystemResolvers)

	h := sha256.New()
	if info.GatewayIP != nil {
		h.Write([]byte(info.GatewayIP.String()))
	}
	h.Write([]byte(info.GatewayMAC))
	h.Write([]byte(n.ssid))
	n.fingerprint = fmt.Sprintf("%x", h.Sum(nil))[:16]
}

func (n *NetEnv) discoverISPHop(ctx context.Context) {
	targetIP := net.ParseIP("1.1.1.1")
	if targetIP == nil {
		return
	}

	for ttl := byte(1); ttl <= 4; ttl++ {
		select {
		case <-ctx.Done():
			return
		default:
		}

		res, err := platform.SendEcho(targetIP, ttl, 1000*time.Millisecond, 1)
		if err != nil || res.ReplyIP == nil {
			continue
		}

		rep := res.ReplyIP
		if n.isPrivateOrGateway(rep) {
			continue
		}

		n.lock.Lock()
		if !rep.Equal(n.ispHopIP) {
			n.ispHopIP = rep
			n.ispHopTTL = ttl
			n.registry.SetISPHop(rep, ttl)
			n.lock.Unlock()
			n.emitSystemEvent(SysEventISPHopChange, fmt.Sprintf("isp hop discovered at %v (ttl=%d)", rep, ttl))
			return
		}
		n.lock.Unlock()
		return
	}
}

func (n *NetEnv) isPrivateOrGateway(ip net.IP) bool {
	n.lock.RLock()
	gw := n.currentInfo.GatewayIP
	n.lock.RUnlock()

	if gw != nil && ip.Equal(gw) {
		return true
	}

	if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return true
	}

	if ip4[0] == 10 {
		return true
	}
	if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
		return true
	}
	if ip4[0] == 192 && ip4[1] == 168 {
		return true
	}

	return false
}

func (n *NetEnv) emitSystemEvent(kind SystemEventKind, detail string) {
	evt := SystemEvent{
		Timestamp: time.Now().UTC().UnixMilli(),
		Kind:      kind,
		Detail:    detail,
	}
	select {
	case n.sysEventCh <- evt:
	default:
	}
}

func (n *NetEnv) GetNetworkInfo() platform.NetworkInfo {
	n.lock.RLock()
	defer n.lock.RUnlock()
	return n.currentInfo
}

func (n *NetEnv) GetFingerprint() string {
	n.lock.RLock()
	defer n.lock.RUnlock()
	return n.fingerprint
}

func (n *NetEnv) IsVPN() bool {
	n.lock.RLock()
	defer n.lock.RUnlock()
	return n.currentInfo.IsVPN
}
