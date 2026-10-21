package probe

import (
	"errors"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func ProbeDNS(target Target, queryName string, timeout time.Duration, seq uint64) ProbeResult {
	sendUTC := time.Now().UTC().UnixMilli()
	sendMono := time.Now().UnixNano()

	if queryName == "" {
		queryName = "www.google.com"
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(queryName), dns.TypeA)
	m.RecursionDesired = true

	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = timeout

	addr := target.Address
	if !strings.Contains(addr, ":") {
		addr = net.JoinHostPort(addr, "53")
	}

	start := time.Now()
	r, rtt, err := c.Exchange(m, addr)
	duration := time.Since(start)

	res := ProbeResult{
		TargetID:    target.ID,
		Target:      target,
		Seq:         seq,
		SendTimeUTC: sendUTC,
		SendMonoNS:  sendMono,
		RTTUS:       duration.Microseconds(),
		Duration:    duration,
	}

	if err == nil {
		res.Reached = true
		if rtt > 0 {
			res.RTTUS = rtt.Microseconds()
		}
		if r.Rcode == dns.RcodeSuccess && len(r.Answer) > 0 {
			res.OK = true
			return res
		}
		res.OK = false
		res.ErrCode = ErrDNSRCode
		res.ErrText = dns.RcodeToString[r.Rcode]
		return res
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		res.Reached = false
		res.OK = false
		res.ErrCode = ErrTimeout
		return res
	}

	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "timeout") {
		res.Reached = false
		res.OK = false
		res.ErrCode = ErrTimeout
		return res
	}
	if strings.Contains(errStr, "refused") {
		res.Reached = true
		res.OK = false
		res.ErrCode = ErrRefused
		return res
	}
	if strings.Contains(errStr, "unreachable") {
		res.Reached = false
		res.OK = false
		res.ErrCode = ErrUnreachable
		return res
	}

	res.Reached = false
	res.OK = false
	res.ErrCode = ErrOther
	res.ErrText = err.Error()
	return res
}
