//go:build !windows

package probe

import (
	"errors"
	"syscall"
)

// classifyDialErrno maps dial errors to a probe error code.
// ok is false when the error isn't one we recognise.
func classifyDialErrno(err error) (code ErrorCode, reached bool, ok bool) {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return ErrNone, false, false
	}
	switch errno {
	case syscall.ECONNREFUSED:
		return ErrRefused, true, true
	case syscall.ECONNRESET:
		return ErrReset, true, true
	case syscall.ENETUNREACH, syscall.EHOSTUNREACH:
		return ErrUnreachable, false, true
	}
	return ErrNone, false, false
}
