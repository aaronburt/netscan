package platform

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi           = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHndl  = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho2  = iphlpapi.NewProc("IcmpSendEcho2")
)

const (
	IPSuccess             = 0
	IPDestNetUnreachable  = 11002
	IPDestHostUnreachable = 11003
	IPReqTimedOut         = 11010
	IPTTLExpiredTransit   = 11013
	IPTTLExpiredReassem   = 11014
	IPGeneralFailure      = 11050
)

type IPOptionInformation struct {
	Ttl         byte
	Tos         byte
	Flags       byte
	OptionsSize byte
	OptionsData uintptr
}

type ICMPEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       IPOptionInformation
}

type ICMPPool struct {
	handles chan windows.Handle
	lock    sync.Mutex
	closed  bool
}

var (
	defaultICMPPool *ICMPPool
	poolOnce        sync.Once
)

func GetICMPPool() (*ICMPPool, error) {
	var initErr error
	poolOnce.Do(func() {
		pool := &ICMPPool{
			handles: make(chan windows.Handle, 8),
		}
		for i := 0; i < 8; i++ {
			r, _, err := procIcmpCreateFile.Call()
			h := windows.Handle(r)
			if h == windows.InvalidHandle {
				initErr = err
				break
			}
			pool.handles <- h
		}
		if initErr == nil {
			defaultICMPPool = pool
		}
	})
	if initErr != nil {
		return nil, initErr
	}
	return defaultICMPPool, nil
}

func (p *ICMPPool) Close() {
	p.lock.Lock()
	defer p.lock.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	close(p.handles)
	for h := range p.handles {
		procIcmpCloseHndl.Call(uintptr(h))
	}
}

func (p *ICMPPool) acquire() (windows.Handle, error) {
	select {
	case h, ok := <-p.handles:
		if !ok {
			return windows.InvalidHandle, errors.New("icmp pool closed")
		}
		return h, nil
	default:
		r, _, err := procIcmpCreateFile.Call()
		h := windows.Handle(r)
		if h == windows.InvalidHandle {
			return windows.InvalidHandle, err
		}
		return h, nil
	}
}

func (p *ICMPPool) release(h windows.Handle) {
	p.lock.Lock()
	defer p.lock.Unlock()
	if p.closed {
		procIcmpCloseHndl.Call(uintptr(h))
		return
	}
	select {
	case p.handles <- h:
	default:
		procIcmpCloseHndl.Call(uintptr(h))
	}
}

// ICMPUnavailable is always nil on Windows, where the ICMP API needs no privileges.
func ICMPUnavailable() error { return nil }

func SendEcho(ip net.IP, ttl byte, timeout time.Duration, seq uint64) (EchoResult, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return EchoResult{}, errors.New("ipv4 required for icmp")
	}

	pool, err := GetICMPPool()
	if err != nil {
		return EchoResult{}, err
	}

	h, err := pool.acquire()
	if err != nil {
		return EchoResult{}, err
	}
	defer pool.release(h)

	destAddr := binary.LittleEndian.Uint32(ip4)

	var opt *IPOptionInformation
	if ttl > 0 {
		opt = &IPOptionInformation{
			Ttl: ttl,
		}
	}

	payload := make([]byte, 32)
	binary.LittleEndian.PutUint64(payload[0:8], seq)
	for i := 8; i < len(payload); i++ {
		payload[i] = byte(i)
	}

	replyBufferSize := uint32(512)
	replyBuffer := make([]byte, replyBufferSize)

	timeoutMS := uint32(timeout.Milliseconds())
	if timeoutMS == 0 {
		timeoutMS = 1000
	}

	start := time.Now()
	ret, _, callErr := procIcmpSendEcho2.Call(
		uintptr(h),
		0,
		0,
		0,
		uintptr(destAddr),
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
		uintptr(unsafe.Pointer(opt)),
		uintptr(unsafe.Pointer(&replyBuffer[0])),
		uintptr(replyBufferSize),
		uintptr(timeoutMS),
	)
	duration := time.Since(start)

	reply := (*ICMPEchoReply)(unsafe.Pointer(&replyBuffer[0]))
	repAddrBytes := *(*[4]byte)(unsafe.Pointer(&reply.Address))
	replyIP := net.IPv4(repAddrBytes[0], repAddrBytes[1], repAddrBytes[2], repAddrBytes[3])

	result := EchoResult{
		DurationUS:  duration.Microseconds(),
		ReplyIP:     replyIP,
		RoundTripMS: reply.RoundTripTime,
	}

	if ret > 0 {
		result.Status = reply.Status
		if reply.Status == IPSuccess {
			result.OK = true
			result.Reached = true
			return result, nil
		}
		if reply.Status == IPTTLExpiredTransit || reply.Status == IPTTLExpiredReassem {
			result.Reached = true
			result.TTLExpired = true
			return result, nil
		}
		if reply.Status == IPDestHostUnreachable || reply.Status == IPDestNetUnreachable {
			result.Reached = false
			result.ErrorMessage = "unreachable"
			return result, nil
		}
		if reply.Status == IPReqTimedOut {
			result.ErrorMessage = "timeout"
			return result, nil
		}
		// The call succeeded, so callErr is whatever GetLastError held from
		// earlier and says nothing about this reply. Report the status.
		result.ErrorMessage = fmt.Sprintf("icmp reply status %d", reply.Status)
		return result, nil
	}

	errCode := uint32(callErr.(windows.Errno))
	result.Status = errCode
	if errCode == IPTTLExpiredTransit || errCode == IPTTLExpiredReassem {
		result.Reached = true
		result.TTLExpired = true
		return result, nil
	}
	if errCode == IPReqTimedOut {
		result.Reached = false
		result.ErrorMessage = "timeout"
		return result, nil
	}
	if errCode == IPDestHostUnreachable || errCode == IPDestNetUnreachable {
		result.Reached = false
		result.ErrorMessage = "unreachable"
		return result, nil
	}

	result.ErrorMessage = callErr.Error()
	return result, nil
}
