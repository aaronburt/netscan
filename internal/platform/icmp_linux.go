//go:build linux

package platform

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var (
	icmpID     = uint16(os.Getpid())
	icmpMode   atomic.Int32 // 0 unknown, 1 raw, 2 unprivileged ping socket
	icmpModeMu sync.Mutex
)

const (
	modeRaw     = 1
	modePing    = 2
	pingNetwork = "udp4"
	rawNetwork  = "ip4:icmp"
)

var (
	icmpCheck    sync.Once
	icmpCheckErr error
)

// ICMPUnavailable returns nil when this process can send echo requests, and
// otherwise why it can't: there is neither a raw socket (root or CAP_NET_RAW)
// nor a ping socket (net.ipv4.ping_group_range must include the process's
// group). The check runs once.
func ICMPUnavailable() error {
	icmpCheck.Do(func() {
		c, _, err := listenICMP()
		if err != nil {
			icmpCheckErr = err
			return
		}
		_ = c.Close()
	})
	return icmpCheckErr
}

// listenICMP opens a raw socket when the process may (root or CAP_NET_RAW)
// and otherwise falls back to an unprivileged ping socket, which needs the
// net.ipv4.ping_group_range sysctl to include the process's group. The
// fallback cannot see TTL-exceeded replies, so hop discovery is disabled there.
func listenICMP() (*icmp.PacketConn, int32, error) {
	if m := icmpMode.Load(); m != 0 {
		network := rawNetwork
		if m == modePing {
			network = pingNetwork
		}
		c, err := icmp.ListenPacket(network, "0.0.0.0")
		return c, m, err
	}
	icmpModeMu.Lock()
	defer icmpModeMu.Unlock()
	if c, err := icmp.ListenPacket(rawNetwork, "0.0.0.0"); err == nil {
		icmpMode.Store(modeRaw)
		return c, modeRaw, nil
	}
	c, err := icmp.ListenPacket(pingNetwork, "0.0.0.0")
	if err != nil {
		return nil, 0, fmt.Errorf("icmp unavailable (need root, CAP_NET_RAW or net.ipv4.ping_group_range): %w", err)
	}
	icmpMode.Store(modePing)
	return c, modePing, nil
}

func SendEcho(ip net.IP, ttl byte, timeout time.Duration, seq uint64) (EchoResult, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return EchoResult{}, errors.New("ipv4 required for icmp")
	}
	if timeout <= 0 {
		timeout = time.Second
	}

	conn, mode, err := listenICMP()
	if err != nil {
		return EchoResult{}, err
	}
	defer conn.Close()

	if ttl > 0 {
		if mode != modeRaw {
			return EchoResult{}, errors.New("ttl-limited icmp needs raw socket privileges")
		}
		if err := conn.IPv4PacketConn().SetTTL(int(ttl)); err != nil {
			return EchoResult{}, err
		}
	}

	seq16 := int(uint16(seq))
	payload := make([]byte, 32)
	for i := range payload {
		payload[i] = byte(i)
	}
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{ID: int(icmpID), Seq: seq16, Data: payload},
	}
	wire, err := msg.Marshal(nil)
	if err != nil {
		return EchoResult{}, err
	}

	var dst net.Addr = &net.IPAddr{IP: ip4}
	if mode == modePing {
		dst = &net.UDPAddr{IP: ip4}
	}

	start := time.Now()
	deadline := start.Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return EchoResult{}, err
	}
	if _, err := conn.WriteTo(wire, dst); err != nil {
		return EchoResult{ErrorMessage: err.Error()}, nil
	}

	buf := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return EchoResult{DurationUS: time.Since(start).Microseconds(), ErrorMessage: "timeout"}, nil
			}
			return EchoResult{DurationUS: time.Since(start).Microseconds(), ErrorMessage: err.Error()}, nil
		}
		elapsed := time.Since(start)
		res, ok := classifyReply(buf[:n], peerIP(peer), seq16, mode == modeRaw)
		if !ok {
			continue
		}
		res.DurationUS = elapsed.Microseconds()
		res.RoundTripMS = uint32(elapsed.Milliseconds())
		return res, nil
	}
}

func peerIP(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.IPAddr:
		return v.IP
	case *net.UDPAddr:
		return v.IP
	}
	return nil
}

// classifyReply interprets a received ICMP message. ok is false when the
// message is not an answer to our probe (raw sockets see all ICMP traffic).
func classifyReply(b []byte, from net.IP, seq int, matchID bool) (EchoResult, bool) {
	m, err := icmp.ParseMessage(1, b)
	if err != nil {
		return EchoResult{}, false
	}
	switch body := m.Body.(type) {
	case *icmp.Echo:
		if m.Type != ipv4.ICMPTypeEchoReply || body.Seq != seq || (matchID && body.ID != int(icmpID)) {
			return EchoResult{}, false
		}
		return EchoResult{OK: true, Reached: true, ReplyIP: from}, true
	case *icmp.TimeExceeded:
		if !matchesInner(body.Data, seq, matchID) {
			return EchoResult{}, false
		}
		return EchoResult{Reached: true, TTLExpired: true, ReplyIP: from, Status: uint32(m.Code)}, true
	case *icmp.DstUnreach:
		if !matchesInner(body.Data, seq, matchID) {
			return EchoResult{}, false
		}
		return EchoResult{ReplyIP: from, Status: uint32(m.Code), ErrorMessage: "unreachable"}, true
	}
	return EchoResult{}, false
}

// matchesInner checks the quoted original datagram (IP header plus the first
// 8 bytes of our echo request) inside an ICMP error.
func matchesInner(data []byte, seq int, matchID bool) bool {
	if len(data) < 20 {
		return false
	}
	ihl := int(data[0]&0x0f) * 4
	if len(data) < ihl+8 || data[9] != 1 || data[ihl] != byte(ipv4.ICMPTypeEcho) {
		return false
	}
	id := int(data[ihl+4])<<8 | int(data[ihl+5])
	s := int(data[ihl+6])<<8 | int(data[ihl+7])
	return s == seq && (!matchID || id == int(icmpID))
}
