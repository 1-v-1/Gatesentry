package gatesentryproxy

// prependConn is a net.Conn wrapper that replays a buffered prefix of bytes
// before reading from the underlying connection. Used when a TLS ClientHello
// (or other protocol bytes) has been peeked from the front of a stream and
// must be re-fed to a downstream TLS handler or tunnel.
//
// Originally defined in transparent_listener.go (linux-only); extracted here
// so the cross-platform SOCKS5 HTTPS path can use it too.

import "net"

type prependConn struct {
	net.Conn
	buf    []byte
	offset int
}

func (c *prependConn) Read(b []byte) (int, error) {
	if c.offset < len(c.buf) {
		n := copy(b, c.buf[c.offset:])
		c.offset += n
		return n, nil
	}
	return c.Conn.Read(b)
}