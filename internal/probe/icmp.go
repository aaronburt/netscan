package probe

import (
	"net"
	"time"

	"github.com/aaronburt/netscan/internal/winapi"
)

func ProbeICMP(target Target, timeout time.Duration, seq uint64) ProbeResult {
	sendUTC := time.Now().UTC().UnixMilli()
	sendMono := time.Now().UnixNano()

	ip := net.ParseIP(target.Address)
	if ip == nil {
		return ProbeResult{
			TargetID:    target.ID,
			Target:      target,
			Seq:         seq,
			SendTimeUTC: sendUTC,
			SendMonoNS:  sendMono,
			Reached:     false,
			OK:          false,
			ErrCode:     ErrOther,
			ErrText:     "invalid ip address",
		}
	}

	echoRes, err := winapi.SendEcho(ip, target.TTL, timeout, seq)
	if err != nil {
		return ProbeResult{
			TargetID:    target.ID,
			Target:      target,
			Seq:         seq,
			SendTimeUTC: sendUTC,
			SendMonoNS:  sendMono,
			Reached:     false,
			OK:          false,
			ErrCode:     ErrLocalError,
			ErrText:     err.Error(),
		}
	}

	res := ProbeResult{
		TargetID:    target.ID,
		Target:      target,
		Seq:         seq,
		SendTimeUTC: sendUTC,
		SendMonoNS:  sendMono,
		Reached:     echoRes.Reached,
		OK:          echoRes.OK,
		RTTUS:       echoRes.DurationUS,
		Duration:    time.Duration(echoRes.DurationUS) * time.Microsecond,
	}

	if echoRes.ReplyIP != nil {
		res.ReplyAddress = echoRes.ReplyIP.String()
	}

	if target.TTL > 0 && echoRes.TTLExpired {
		res.Reached = true
		res.OK = true
		return res
	}

	if !echoRes.Reached {
		if echoRes.ErrorMessage == "timeout" {
			res.ErrCode = ErrTimeout
		} else if echoRes.ErrorMessage == "unreachable" {
			res.ErrCode = ErrUnreachable
		} else {
			res.ErrCode = ErrLocalError
			res.ErrText = echoRes.ErrorMessage
		}
	}

	return res
}
