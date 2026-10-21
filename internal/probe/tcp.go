package probe

import (
	"errors"
	"net"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

func ProbeTCP(target Target, timeout time.Duration, seq uint64) ProbeResult {
	sendUTC := time.Now().UTC().UnixMilli()
	sendMono := time.Now().UnixNano()

	dialer := net.Dialer{
		Timeout: timeout,
	}

	start := time.Now()
	conn, err := dialer.Dial("tcp4", target.Address)
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
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetLinger(0)
		}
		_ = conn.Close()
		res.Reached = true
		res.OK = true
		return res
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		res.Reached = false
		res.OK = false
		res.ErrCode = ErrTimeout
		return res
	}

	var errno windows.Errno
	if errors.As(err, &errno) {
		if errno == windows.WSAECONNREFUSED {
			res.Reached = true
			res.OK = false
			res.ErrCode = ErrRefused
			return res
		}
		if errno == windows.WSAECONNRESET {
			res.Reached = true
			res.OK = false
			res.ErrCode = ErrReset
			return res
		}
		if errno == windows.WSAENETUNREACH || errno == windows.WSAEHOSTUNREACH {
			res.Reached = false
			res.OK = false
			res.ErrCode = ErrUnreachable
			return res
		}
	}

	var sysErr syscall.Errno
	if errors.As(err, &sysErr) {
		if sysErr == syscall.ECONNREFUSED {
			res.Reached = true
			res.OK = false
			res.ErrCode = ErrRefused
			return res
		}
		if sysErr == syscall.ECONNRESET {
			res.Reached = true
			res.OK = false
			res.ErrCode = ErrReset
			return res
		}
	}

	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "refused") {
		res.Reached = true
		res.OK = false
		res.ErrCode = ErrRefused
		return res
	}
	if strings.Contains(errStr, "reset") {
		res.Reached = true
		res.OK = false
		res.ErrCode = ErrReset
		return res
	}
	if strings.Contains(errStr, "timeout") {
		res.Reached = false
		res.OK = false
		res.ErrCode = ErrTimeout
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
