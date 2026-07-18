package gatesentryDnsServer

// SOCKS5 UDP ASSOCIATE for the DNS forwarder.
//
// When `egress_socks5` is set, all of Gatesentry's outbound traffic —
// including DNS — must go through the upstream SOCKS5. The DNS
// forwarder normally does a raw UDP dial to the configured external
// resolver (e.g. 8.8.8.8:53) via miekg/dns. This file implements a
// SOCKS5 UDP ASSOCIATE client that lets the DNS forwarder reach the
// resolver through the SOCKS5 server as if it were a direct UDP socket.
//
// Protocol (RFC 1928 §7):
//
//  1. Client opens a TCP control connection to the SOCKS5 server and
//     negotiates auth (we use NoAuth).
//  2. Client sends VER=5 CMD=3 (UDP ASSOCIATE) RSV=0 ATYP=1 ADDR=0.0.0.0
//     PORT=0.
//  3. Server replies with VER REP RSV ATYP BND.ADDR BND.PORT — the
//     address of the SOCKS5 server's UDP relay.
//  4. Client opens a local UDP socket. For each datagram to send, it
//     prepends a SOCKS5 UDP header (RSV=0 FRAG=0 ATYP/DST.ADDR/DST.PORT)
//     and sends the result to BND.ADDR:BND.PORT. The SOCKS5 server
//     strips the header and forwards the payload to the real DST.
//  5. Responses come back the same way, wrapped in a SOCKS5 UDP header
//     whose DST.ADDR/BND.PORT is the upstream target. Client strips
//     the header and yields the payload.
//
// We implement this as a net.Conn that wraps the SOCKS5 association.
// miekg/dns can use it via dns.Client.ExchangeWithConn + dns.Conn{Conn: ...}.

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"
	"time"
)

// DialSOCKS5UDP opens a "virtual" UDP connection to target through a
// SOCKS5 server. Returns a net.Conn whose Read/Write exchange SOCKS5 UDP
// datagrams; Close tears down the SOCKS5 association.
//
// Used by the DNS forwarder so external resolver queries (e.g.
// 8.8.8.8:53) travel through the configured upstream SOCKS5.
//
// socksServer: "host:port" of the SOCKS5 server
// target:      "host:port" of the upstream DNS resolver
// user, pass:  optional SOCKS5 credentials (empty = no auth)
func DialSOCKS5UDP(socksServer, target, user, pass string) (net.Conn, error) {
	// 1. Open TCP control connection.
	control, err := net.DialTimeout("tcp", socksServer, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("socks5 udp: dial %s: %w", socksServer, err)
	}
	if err := control.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		control.Close()
		return nil, err
	}

	// 2. Greeting: VER=5 NAUTH=n METHODS...
	// We try NoAuth first; if the server requires user/pass we fall
	// back to RFC 1929 subnegotiation.
	if err := socks5Greet(control, user, pass); err != nil {
		control.Close()
		return nil, err
	}

	// 3. UDP ASSOCIATE: ATYP=1, ADDR=0.0.0.0, PORT=0 (let server pick).
	if _, err := control.Write([]byte{
		0x05, 0x03, 0x00,
		0x01, // ATYP IPv4
		0, 0, 0, 0, // 0.0.0.0
		0, 0, // port 0
	}); err != nil {
		control.Close()
		return nil, fmt.Errorf("socks5 udp: send ASSOCIATE: %w", err)
	}

	// 4. Read reply: VER REP RSV ATYP BND.ADDR BND.PORT (>=10 bytes for IPv4).
	header := make([]byte, 4)
	if _, err := readFull(control, header); err != nil {
		control.Close()
		return nil, fmt.Errorf("socks5 udp: read reply header: %w", err)
	}
	if header[0] != 0x05 {
		control.Close()
		return nil, fmt.Errorf("socks5 udp: bad version %d", header[0])
	}
	if header[1] != 0x00 {
		control.Close()
		return nil, fmt.Errorf("socks5 udp: server REP=%d (not success)", header[1])
	}
	var bnd *net.UDPAddr
	switch header[3] {
	case 0x01: // IPv4
		rest := make([]byte, 4+2)
		if _, err := readFull(control, rest); err != nil {
			control.Close()
			return nil, err
		}
		bnd = &net.UDPAddr{
			IP:   net.IP(rest[:4]),
			Port: int(binary.BigEndian.Uint16(rest[4:])),
		}
	case 0x04: // IPv6
		rest := make([]byte, 16+2)
		if _, err := readFull(control, rest); err != nil {
			control.Close()
			return nil, err
		}
		bnd = &net.UDPAddr{
			IP:   net.IP(rest[:16]),
			Port: int(binary.BigEndian.Uint16(rest[16:])),
		}
	default:
		control.Close()
		return nil, fmt.Errorf("socks5 udp: unsupported ATYP %d", header[3])
	}

	// 5. Open local UDP socket for relaying.
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		control.Close()
		return nil, fmt.Errorf("socks5 udp: listenUDP: %w", err)
	}

	return &socks5UDPConn{
		control:   control,
		udp:       udp,
		bnd:       bnd,
		target:    target,
		readBuf:   make([]byte, 65535),
	}, nil
}

// socks5Greet negotiates the SOCKS5 greeting. Tries NoAuth first; if
// the server requires user/pass and credentials are provided, falls
// back to RFC 1929 subnegotiation.
func socks5Greet(control net.Conn, user, pass string) error {
	methods := []byte{0x00}
	if user != "" {
		methods = []byte{0x00, 0x02}
	}
	if _, err := control.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		return fmt.Errorf("socks5 udp: send greeting: %w", err)
	}
	reply := make([]byte, 2)
	if _, err := readFull(control, reply); err != nil {
		return fmt.Errorf("socks5 udp: read greeting reply: %w", err)
	}
	if reply[0] != 0x05 {
		return fmt.Errorf("socks5 udp: bad greeting version %d", reply[0])
	}
	switch reply[1] {
	case 0x00:
		return nil
	case 0x02:
		if user == "" {
			return fmt.Errorf("socks5 udp: server requires user/pass but no creds provided")
		}
		return socks5UserPass(control, user, pass)
	case 0xFF:
		return fmt.Errorf("socks5 udp: no acceptable auth method")
	default:
		return fmt.Errorf("socks5 udp: unexpected method %d", reply[1])
	}
}

// socks5UserPass performs RFC 1929 username/password subnegotiation.
func socks5UserPass(control net.Conn, user, pass string) error {
	if len(user) > 255 || len(pass) > 255 {
		return fmt.Errorf("socks5 udp: user/pass too long")
	}
	req := []byte{0x01, byte(len(user))}
	req = append(req, user...)
	req = append(req, byte(len(pass)))
	req = append(req, pass...)
	if _, err := control.Write(req); err != nil {
		return fmt.Errorf("socks5 udp: send userpass: %w", err)
	}
	reply := make([]byte, 2)
	if _, err := readFull(control, reply); err != nil {
		return err
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("socks5 udp: user/pass auth failed (status %d)", reply[1])
	}
	return nil
}

// socks5UDPConn is the net.Conn that wraps a SOCKS5 UDP association.
type socks5UDPConn struct {
	control net.Conn     // TCP control to SOCKS5 server (kept open)
	udp     *net.UDPConn // local UDP socket for relaying
	bnd     *net.UDPAddr // BND.ADDR:BND.PORT from ASSOCIATE reply
	target  string       // upstream target "host:port" for header
	readBuf []byte
	closed  atomic.Bool
}

func (c *socks5UDPConn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	var err1, err2 error
	if c.udp != nil {
		err1 = c.udp.Close()
	}
	if c.control != nil {
		err2 = c.control.Close()
	}
	if err1 != nil {
		return err1
	}
	return err2
}

func (c *socks5UDPConn) LocalAddr() net.Addr {
	if c.udp != nil {
		return c.udp.LocalAddr()
	}
	return &net.UDPAddr{}
}

func (c *socks5UDPConn) RemoteAddr() net.Addr {
	return c.bnd
}

func (c *socks5UDPConn) SetDeadline(t time.Time) error {
	if err := c.udp.SetDeadline(t); err != nil {
		return err
	}
	return c.control.SetDeadline(t)
}

func (c *socks5UDPConn) SetReadDeadline(t time.Time) error  { return c.udp.SetReadDeadline(t) }
func (c *socks5UDPConn) SetWriteDeadline(t time.Time) error { return c.udp.SetWriteDeadline(t) }

// Read blocks for a UDP datagram from the SOCKS5 server, strips the
// SOCKS5 UDP header, and copies the payload into b.
func (c *socks5UDPConn) Read(b []byte) (int, error) {
	for {
		n, _, err := c.udp.ReadFromUDP(c.readBuf)
		if err != nil {
			return 0, err
		}
		if n < 4 {
			continue // malformed, drop
		}
		// Verify RSV (2 bytes) and FRAG (1 byte).
		if c.readBuf[0] != 0 || c.readBuf[1] != 0 || c.readBuf[2] != 0 {
			continue
		}
		dataOff, ok := socks5UDPHeaderSize(c.readBuf[:n])
		if !ok {
			continue
		}
		return copy(b, c.readBuf[dataOff:n]), nil
	}
}

// Write sends a UDP datagram to the upstream target via the SOCKS5
// server: prepends the SOCKS5 UDP header and writes to the local UDP
// socket addressed to BND.ADDR:BND.PORT.
func (c *socks5UDPConn) Write(b []byte) (int, error) {
	header, err := buildSOCKS5UDPHeader(c.target)
	if err != nil {
		return 0, err
	}
	pkt := make([]byte, 0, len(header)+len(b))
	pkt = append(pkt, header...)
	pkt = append(pkt, b...)
	if _, err := c.udp.WriteToUDP(pkt, c.bnd); err != nil {
		return 0, err
	}
	return len(b), nil
}

// socks5UDPHeaderSize parses the SOCKS5 UDP header and returns the
// offset where the payload starts. ok=false if the header is malformed.
func socks5UDPHeaderSize(buf []byte) (int, bool) {
	if len(buf) < 4 {
		return 0, false
	}
	atyp := buf[3]
	switch atyp {
	case 0x01: // IPv4
		if len(buf) < 10 {
			return 0, false
		}
		return 10, true
	case 0x03: // domain
		if len(buf) < 5 {
			return 0, false
		}
		dlen := int(buf[4])
		if len(buf) < 4+1+dlen+2 {
			return 0, false
		}
		return 4 + 1 + dlen + 2, true
	case 0x04: // IPv6
		if len(buf) < 22 {
			return 0, false
		}
		return 22, true
	default:
		return 0, false
	}
}

// buildSOCKS5UDPHeader builds the SOCKS5 UDP request header for the
// given target "host:port".
func buildSOCKS5UDPHeader(target string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("socks5 udp: bad target %q: %w", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("socks5 udp: bad port %q: %w", portStr, err)
	}
	hdr := []byte{0x00, 0x00, 0x00} // RSV, FRAG
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			hdr = append(hdr, 0x01)
			hdr = append(hdr, ip4...)
		} else {
			hdr = append(hdr, 0x04)
			hdr = append(hdr, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("socks5 udp: hostname too long")
		}
		hdr = append(hdr, 0x03, byte(len(host)))
		hdr = append(hdr, host...)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	hdr = append(hdr, portBytes...)
	return hdr, nil
}

func readFull(c net.Conn, b []byte) (int, error) {
	n, err := c.Read(b)
	if err != nil {
		return n, err
	}
	for n < len(b) {
		nn, err := c.Read(b[n:])
		if err != nil {
			return n, err
		}
		n += nn
	}
	return n, nil
}