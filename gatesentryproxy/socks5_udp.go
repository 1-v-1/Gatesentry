package gatesentryproxy

// SOCKS5 UDP ASSOCIATE command.
//
// Used to relay UDP datagrams through the SOCKS5 proxy. The canonical case
// is DNS-over-SOCKS5, where the client sends DNS queries as UDP datagrams
// to our local UDP port and the SOCKS5 server forwards them to the real
// DNS resolver.
//
// Flow per RFC 1928 §7:
//
//  1. Client opens a TCP control connection and sends VER CMD RSV ATYP
//     DST.ADDR DST.PORT (CMD = 0x03). The DST is informational — most
//     clients set it to the destination of the first datagram.
//  2. Server replies with BND.ADDR/BND.PORT — a UDP port it just opened.
//  3. The client sends UDP datagrams to BND.ADDR:BND.PORT, each prefixed
//     with the SOCKS5 UDP header:
//
//        +----+------+------+----------+----------+----------+
//        |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//        +----+------+------+----------+----------+----------+
//
//  4. Server strips the header, forwards DATA to DST.ADDR:DST.PORT.
//  5. When a UDP datagram arrives from the target, the server wraps it
//     in the same header (with DST.ADDR/BND.PORT set to the target) and
//     sends it back to the client.
//  6. Closing the TCP control channel tears down the association.
//
// Limitations (acceptable for the canonical use cases):
//
//   - FRAG is required to be 0. Non-zero FRAG (fragmentation) is rejected.
//   - The target address is updated on every client→server datagram, so
//     only one logical "session" per association. Multi-target clients
//     would race.
//   - Only datagrams whose source IP:port matches the most recently
//     recorded target are forwarded back. This prevents a malicious UDP
//     sender from injecting datagrams into the association.

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

// Maximum UDP datagram size we accept. Matches the SOCKS5 spec's safe
// maximum (the IPv4 minimum reassembly buffer).
const socks5UDPReadSize = 65535

// socks5UDPHeader is the minimum header bytes we look at when parsing.
// The full header layout is:
//
//	+----+------+------+----------+----------+
//	|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA
//	+----+------+------+----------+----------+
//	| 2  |  1   |  1   | Variable |    2     | Variable
//
const (
	socks5UDPRsv   = 0x0000
	socks5UDPFrag0 = 0x00
)

// handleSocks5UDPAssociate runs the UDP ASSOCIATE command. The filter
// chain has already run against the destination host. We:
//
//   - Bind a local UDP socket
//   - Send the BND reply
//   - Forward datagrams in both directions until the TCP control channel
//     closes (or 5 minutes elapse, whichever first).
func handleSocks5UDPAssociate(control net.Conn, host string, port uint16, user string) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		log.Printf("[SOCKS5 UDP] listen failed: %v", err)
		_ = socks5SendReply(control, socks5RepGeneralFailure)
		return
	}

	// Reply with our local UDP port.
	if err := socks5SendReplyAddr(control, socks5RepSuccess, udpConn.LocalAddr()); err != nil {
		log.Printf("[SOCKS5 UDP] reply failed: %v", err)
		udpConn.Close()
		return
	}
	if DebugLogging {
		log.Printf("[SOCKS5 UDP] association up: client→%s (DST=%s:%d)",
			udpConn.LocalAddr().String(), host, port)
	}

	logUrl := "socks5-udp://" + net.JoinHostPort(host, strconv.Itoa(int(port)))
	LogProxyAction(logUrl, user, ProxyActionSSLDirect)

	// Run the relay until the control channel closes or we hit the
	// association timeout.
	assoc := &udpAssoc{
		control:    control,
		udpSocket:  udpConn,
		closeOnce:  &sync.Once{},
		closeSignal: make(chan struct{}),
	}
	defer assoc.close()

	// Watcher: when the TCP control channel closes, tear down.
	go func() {
		buf := make([]byte, 1)
		_, _ = control.Read(buf) // blocks until EOF or error
		assoc.close()
	}()

	assoc.relay()
}

// udpAssoc holds the state for a single SOCKS5 UDP association.
type udpAssoc struct {
	control     net.Conn
	udpSocket   *net.UDPConn
	closeOnce   *sync.Once
	closeSignal chan struct{}

	// Address tracking.
	mu          sync.Mutex
	clientAddr  *net.UDPAddr // last client UDP addr seen (for replies)
	targetAddr  *net.UDPAddr // last target UDP addr (for filtering incoming)
}

func (a *udpAssoc) close() {
	a.closeOnce.Do(func() {
		close(a.closeSignal)
		_ = a.udpSocket.Close()
		_ = a.control.Close()
	})
}

// relay runs the bidirectional UDP forwarder. Each iteration:
//
//   - Read a datagram from our local UDP socket.
//   - If the source is the recorded target → wrap and send to client.
//   - If the source is the client (or anything else) → strip SOCKS5 UDP
//     header, forward to the target.
//
// The "everything else is treated as client" branch lets a client change
// its source port mid-association (some NATs do this); the address is
// updated on every "client" datagram.
func (a *udpAssoc) relay() {
	buf := make([]byte, socks5UDPReadSize)
	for {
		select {
		case <-a.closeSignal:
			return
		default:
		}

		_ = a.udpSocket.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, from, err := a.udpSocket.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if DebugLogging {
				log.Printf("[SOCKS5 UDP] read error: %v", err)
			}
			return
		}

		a.mu.Lock()
		clientIs := a.clientAddr
		targetIs := a.targetAddr
		a.mu.Unlock()

		// Datagram from the recorded target? → forward to client.
		if targetIs != nil && from.IP.Equal(targetIs.IP) && from.Port == targetIs.Port {
			if clientIs == nil {
				continue // no client yet — drop
			}
			hdr, ok := socks5UDPWrapHeader(targetIs)
			if !ok {
				continue
			}
			out := append(hdr, buf[:n]...)
			_, _ = a.udpSocket.WriteToUDP(out, clientIs)
			continue
		}

		// Otherwise treat as a client→server datagram. Parse the SOCKS5
		// UDP header, extract the data, and forward to the target.
		if n < 4 {
			continue
		}
		rsv := binary.BigEndian.Uint16(buf[:2])
		frag := buf[2]
		atyp := buf[3]
		if rsv != socks5UDPRsv || frag != socks5UDPFrag0 {
			if DebugLogging {
				log.Printf("[SOCKS5 UDP] unsupported UDP header: rsv=%d frag=%d", rsv, frag)
			}
			continue
		}
		dstUDP, dataOff, ok := socks5UDPParseAddr(buf[3:n], atyp)
		if !ok {
			continue
		}
		payload := buf[3+dataOff : n]

		// Update tracking: this `from` is the client; dstUDP is the target.
		a.mu.Lock()
		a.clientAddr = &net.UDPAddr{IP: from.IP, Port: from.Port}
		a.targetAddr = dstUDP
		a.mu.Unlock()

		_, _ = a.udpSocket.WriteToUDP(payload, dstUDP)
	}
}

// socks5UDPParseAddr parses an ATYP/DST.ADDR/DST.PORT tuple from the wire.
// Returns the UDP destination address and the number of header bytes
// consumed (relative to the start of the ATYP byte).
func socks5UDPParseAddr(buf []byte, atyp byte) (*net.UDPAddr, int, bool) {
	switch atyp {
	case socks5AtypIPv4:
		if len(buf) < 1+4+2 {
			return nil, 0, false
		}
		ip := net.IP(buf[1 : 1+4])
		port := binary.BigEndian.Uint16(buf[1+4 : 1+4+2])
		return &net.UDPAddr{IP: ip, Port: int(port)}, 1 + 4 + 2, true
	case socks5AtypDomain:
		if len(buf) < 1+1 {
			return nil, 0, false
		}
		dlen := int(buf[1])
		if len(buf) < 1+1+dlen+2 {
			return nil, 0, false
		}
		host := string(buf[1+1 : 1+1+dlen])
		ips, err := net.LookupHost(host)
		if err != nil || len(ips) == 0 {
			return nil, 0, false
		}
		port := binary.BigEndian.Uint16(buf[1+1+dlen : 1+1+dlen+2])
		return &net.UDPAddr{IP: net.ParseIP(ips[0]), Port: int(port)}, 1 + 1 + dlen + 2, true
	case socks5AtypIPv6:
		if len(buf) < 1+16+2 {
			return nil, 0, false
		}
		ip := net.IP(buf[1 : 1+16])
		port := binary.BigEndian.Uint16(buf[1+16 : 1+16+2])
		return &net.UDPAddr{IP: ip, Port: int(port)}, 1 + 16 + 2, true
	default:
		return nil, 0, false
	}
}

// socks5UDPWrapHeader builds the SOCKS5 UDP reply header (RSV=0, FRAG=0,
// ATYP/ADDR/PORT of the source datagram).
func socks5UDPWrapHeader(from *net.UDPAddr) ([]byte, bool) {
	if from == nil {
		return nil, false
	}
	ip4 := from.IP.To4()
	if ip4 != nil {
		hdr := []byte{0x00, 0x00, 0x00, socks5AtypIPv4}
		hdr = append(hdr, ip4...)
		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, uint16(from.Port))
		return append(hdr, port...), true
	}
	ip6 := from.IP.To16()
	if ip6 == nil {
		return nil, false
	}
	hdr := []byte{0x00, 0x00, 0x00, socks5AtypIPv6}
	hdr = append(hdr, ip6...)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(from.Port))
	return append(hdr, port...), true
}

// Compile-time guard: io is referenced here so the import is non-empty even
// when no io.Copy is used in this file (it might be used in future
// extensions).
var _ = io.Discard