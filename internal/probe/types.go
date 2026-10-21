package probe

import (
	"fmt"
	"time"
)

type ErrorCode int

const (
	ErrNone ErrorCode = iota
	ErrTimeout
	ErrUnreachable
	ErrRefused
	ErrReset
	ErrDNSRCode
	ErrTLS
	ErrHTTPUnexpected
	ErrOSDNS
	ErrLocalError
	ErrSkipped
	ErrOther
)

func (e ErrorCode) String() string {
	switch e {
	case ErrNone:
		return "NONE"
	case ErrTimeout:
		return "TIMEOUT"
	case ErrUnreachable:
		return "UNREACHABLE"
	case ErrRefused:
		return "REFUSED"
	case ErrReset:
		return "RESET"
	case ErrDNSRCode:
		return "DNS_RCODE"
	case ErrTLS:
		return "TLS"
	case ErrHTTPUnexpected:
		return "HTTP_UNEXPECTED"
	case ErrOSDNS:
		return "OS_DNS"
	case ErrLocalError:
		return "LOCAL_ERROR"
	case ErrSkipped:
		return "SKIPPED"
	case ErrOther:
		return "OTHER"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", e)
	}
}

func (e ErrorCode) MarshalText() ([]byte, error) {
	return []byte(e.String()), nil
}

func (e *ErrorCode) UnmarshalText(text []byte) error {
	switch string(text) {
	case "NONE", "":
		*e = ErrNone
	case "TIMEOUT":
		*e = ErrTimeout
	case "UNREACHABLE":
		*e = ErrUnreachable
	case "REFUSED":
		*e = ErrRefused
	case "RESET":
		*e = ErrReset
	case "DNS_RCODE":
		*e = ErrDNSRCode
	case "TLS":
		*e = ErrTLS
	case "HTTP_UNEXPECTED":
		*e = ErrHTTPUnexpected
	case "OS_DNS":
		*e = ErrOSDNS
	case "LOCAL_ERROR":
		*e = ErrLocalError
	case "SKIPPED":
		*e = ErrSkipped
	case "OTHER":
		*e = ErrOther
	default:
		*e = ErrOther
	}
	return nil
}

const (
	FlagFastMode   = 1 << 0
	FlagLatency    = 1 << 1
	FlagSpike      = 1 << 2
	FlagPostResume = 1 << 3
	FlagVPN        = 1 << 4
	FlagSkipped    = 1 << 5
)

type Layer string

const (
	LayerGateway Layer = "gateway"
	LayerISPHop  Layer = "isp_hop"
	LayerWANICMP Layer = "wan_icmp"
	LayerWANTCP  Layer = "wan_tcp"
	LayerDNS     Layer = "dns"
	LayerHTTP    Layer = "http"
)

type Target struct {
	ID         int    `json:"id"`
	Layer      Layer  `json:"layer"`
	Address    string `json:"address"`
	Label      string `json:"label"`
	Expected   int    `json:"expected,omitempty"`
	BodyPrefix string `json:"body_prefix,omitempty"`
	TTL        byte   `json:"ttl,omitempty"`
}

type ProbeResult struct {
	TargetID     int           `json:"target_id"`
	Target       Target        `json:"target"`
	Seq          uint64        `json:"seq"`
	SendTimeUTC  int64         `json:"ts_ms"`
	SendMonoNS   int64         `json:"-"`
	Reached      bool          `json:"reached"`
	OK           bool          `json:"ok"`
	RTTUS        int64         `json:"rtt_us"`
	ErrCode      ErrorCode     `json:"err"`
	ErrText      string        `json:"err_text,omitempty"`
	Flags        int           `json:"flags"`
	DNSUS        int64         `json:"dns_us,omitempty"`
	TCPUS        int64         `json:"tcp_us,omitempty"`
	TLSUS        int64         `json:"tls_us,omitempty"`
	TTFBUS       int64         `json:"ttfb_us,omitempty"`
	HTTPStatus   int           `json:"status,omitempty"`
	ReplyAddress string        `json:"reply_address,omitempty"`
	Duration     time.Duration `json:"-"`
}
