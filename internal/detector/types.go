package detector

import (
	"fmt"
	"time"

	"github.com/aaronburt/netscan/internal/probe"
)

type State int

const (
	StateHealthy State = iota
	StateDegraded
	StateOutage
	StateRecovering
	StateSuspended
	StatePaused
)

func (s State) String() string {
	switch s {
	case StateHealthy:
		return "HEALTHY"
	case StateDegraded:
		return "DEGRADED"
	case StateOutage:
		return "OUTAGE"
	case StateRecovering:
		return "RECOVERING"
	case StateSuspended:
		return "SUSPENDED"
	case StatePaused:
		return "PAUSED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", s)
	}
}

type LayerStatus int

const (
	LayerStatusUnknown LayerStatus = iota
	LayerStatusUp
	LayerStatusSuspect
	LayerStatusDown
)

func (ls LayerStatus) String() string {
	switch ls {
	case LayerStatusUnknown:
		return "UNKNOWN"
	case LayerStatusUp:
		return "UP"
	case LayerStatusSuspect:
		return "SUSPECT"
	case LayerStatusDown:
		return "DOWN"
	default:
		return "UNKNOWN"
	}
}

type EventKind string

const (
	EventKindOutage  EventKind = "outage"
	EventKindBlip    EventKind = "blip"
	EventKindLatency EventKind = "latency"
)

type Classification string

const (
	ClassLinkDown     Classification = "LINK_DOWN"
	ClassGateway      Classification = "GATEWAY"
	ClassISPEdge      Classification = "ISP_EDGE"
	ClassWAN          Classification = "WAN"
	ClassDNSSystem    Classification = "DNS_SYSTEM"
	ClassDNSAll       Classification = "DNS_ALL"
	ClassHTTP         Classification = "HTTP"
	ClassCaptive      Classification = "CAPTIVE"
	ClassLatencyLocal Classification = "LATENCY_LOCAL"
	ClassLatencyWAN   Classification = "LATENCY_WAN"
	ClassICMPFiltered Classification = "ICMP_FILTERED"
)

const (
	LayerMaskLink    = 1 << 0
	LayerMaskGateway = 1 << 1
	LayerMaskISPEdge = 1 << 2
	LayerMaskWANICMP = 1 << 3
	LayerMaskWANTCP  = 1 << 4
	LayerMaskDNS     = 1 << 5
	LayerMaskHTTP    = 1 << 6
)

const (
	EventFlagInterrupted = 1 << 0
	EventFlagPostResume  = 1 << 1
	EventFlagVPN         = 1 << 2
)

type Event struct {
	ID             int64          `json:"id"`
	Kind           EventKind      `json:"kind"`
	Classification Classification `json:"classification"`
	NetworkID      int64          `json:"network_id"`
	StartMS        int64          `json:"start_ms"`
	StartUncertMS  int64          `json:"start_uncert_ms"`
	EndMS          *int64         `json:"end_ms,omitempty"`
	EndUncertMS    *int64         `json:"end_uncert_ms,omitempty"`
	DurationMS     *int64         `json:"duration_ms,omitempty"`
	LayersDown     int            `json:"layers_down"`
	Flags          int            `json:"flags"`
	GatewayOKPct   float64        `json:"gateway_ok_pct"`
	ISPHopOKPct    float64        `json:"isp_hop_ok_pct"`
	ContextJSON    string         `json:"context,omitempty"`
}

type Snapshot struct {
	TimestampMS   int64                       `json:"ts_ms"`
	State         State                       `json:"state"`
	StateString   string                      `json:"state_string"`
	FastMode      bool                        `json:"fast_mode"`
	LayerStatuses map[probe.Layer]LayerStatus `json:"layer_statuses"`
	LatestRTTUS   map[int]int64               `json:"latest_rtt_us"`
	OpenEvent     *Event                      `json:"open_event,omitempty"`
	LastEvent     *Event                      `json:"last_event,omitempty"`
}

type Clock interface {
	Now() time.Time
}

type RealClock struct{}

func (RealClock) Now() time.Time {
	return time.Now()
}
