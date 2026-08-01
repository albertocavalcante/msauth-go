package msauth

import (
	"context"
	"fmt"
	"net"
)

// loopbackListeners binds a single port on BOTH 127.0.0.1 and ::1 so a browser
// redirected to http://localhost:<port> reaches us regardless of how it
// resolves "localhost". This is the fix for MSAL Go's built-in interactive
// server, which binds only one stack via net.Listen("tcp", "localhost:port")
// and so intermittently yields "localhost refused to connect" on macOS.
//
// The IPv4 listener is required; the IPv6 listener is best-effort (nil when the
// host has no usable ::1). The caller must Close both.
func loopbackListeners(ctx context.Context) (v4, v6 net.Listener, port int, err error) {
	var lc net.ListenConfig
	v4, err = lc.Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, nil, 0, fmt.Errorf("bind 127.0.0.1: %w", err)
	}
	port = v4.Addr().(*net.TCPAddr).Port
	if l6, err6 := lc.Listen(ctx, "tcp6", fmt.Sprintf("[::1]:%d", port)); err6 == nil {
		v6 = l6
	}
	return v4, v6, port, nil
}
