package probe

import (
	"errors"

	"golang.org/x/sys/windows"
)

// classifyDialErrno maps Winsock dial errors to a probe error code.
// ok is false when the error isn't one we recognise.
func classifyDialErrno(err error) (code ErrorCode, reached bool, ok bool) {
	var errno windows.Errno
	if !errors.As(err, &errno) {
		return ErrNone, false, false
	}
	switch errno {
	case windows.WSAECONNREFUSED:
		return ErrRefused, true, true
	case windows.WSAECONNRESET:
		return ErrReset, true, true
	case windows.WSAENETUNREACH, windows.WSAEHOSTUNREACH:
		return ErrUnreachable, false, true
	}
	return ErrNone, false, false
}
