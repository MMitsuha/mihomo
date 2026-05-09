package tunnel

import (
	"net"
	"sync/atomic"

	C "github.com/metacubex/mihomo/constant"
)

// MitmIntercept is consulted at the top of handleTCPConn before rule
// resolution. If it returns true the connection is considered fully handled
// and the tunnel does nothing else with it. Returning false lets normal
// rule-based dispatch proceed.
type MitmIntercept func(conn net.Conn, metadata *C.Metadata) bool

var mitmIntercept atomic.Pointer[MitmIntercept]

// SetMitmIntercept installs the interceptor. Pass nil to clear it.
func SetMitmIntercept(fn MitmIntercept) {
	if fn == nil {
		mitmIntercept.Store(nil)
		return
	}
	mitmIntercept.Store(&fn)
}

func tryMitmIntercept(conn net.Conn, metadata *C.Metadata) bool {
	if metadata == nil || metadata.Intercepted {
		return false
	}
	h := mitmIntercept.Load()
	if h == nil {
		return false
	}
	return (*h)(conn, metadata)
}
