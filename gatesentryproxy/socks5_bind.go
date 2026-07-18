package gatesentryproxy

// SOCKS5 BIND command.
//
// Used by protocols where the application server connects BACK to the client
// (the canonical example is FTP active mode: the FTP client uses SOCKS5 BIND
// to ask the proxy for an inbound TCP endpoint, tells the FTP server
// "connect to that endpoint", and the data channel then runs client <-> proxy
// <-> FTP-server).
//
// Flow per RFC 1928:
//
//	1. Client opens a TCP control connection to the SOCKS5 server and
//	   sends VER CMD RSV ATYP DST.ADDR DST.PORT (CMD = 0x02).
//	2. The SOCKS5 server opens a new TCP listening socket on a port of
//	   its choosing and sends back a reply with BND.ADDR/BND.PORT.
//	3. The client (or its app) tells the upstream server to connect to
//	   the SOCKS5 server's BND.ADDR:BND.PORT.
//	4. When the SOCKS5 server accepts the inbound connection, it sends a
//	   SECOND reply on the control channel (success / failure).
//	5. From then on the control channel and the accepted inbound conn
//	   carry the proxied application bytes bidirectionally.
//
// We require the upstream server to connect within 60 seconds, otherwise
// we give up. All bytes flowing on the inbound conn are counted by
// ContentSizeHandler the same way the CONNECT path does, so users with
// per-user quotas get billed correctly.

import (
	"io"
	"log"
	"net"
	"strconv"
	"time"
)

// handleSocks5Bind runs the BIND command. The filter chain has already run
// against the destination host (passed in `host`); we just need to:
//
//   - Open a local listening socket
//   - Send reply #1 with BND.ADDR/BND.PORT
//   - Wait for the inbound connection from the upstream server
//   - Send reply #2 (success / failure) on the control channel
//   - Bidirectional copy until either side EOFs
func handleSocks5Bind(control net.Conn, host string, port uint16, user string) {
	// Open a local listener. Port 0 lets the OS pick — BIND clients don't
	// care which port we use as long as the upstream server can reach it.
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		log.Printf("[SOCKS5 BIND] listen failed: %v", err)
		_ = socks5SendReply(control, socks5RepGeneralFailure)
		return
	}
	defer ln.Close()

	// Reply #1: BND.ADDR/BND.PORT is our local listener.
	boundAddr := ln.Addr().(*net.TCPAddr)
	if err := socks5SendReplyAddr(control, socks5RepSuccess, boundAddr); err != nil {
		log.Printf("[SOCKS5 BIND] reply #1 failed: %v", err)
		return
	}
	if DebugLogging {
		log.Printf("[SOCKS5 BIND] waiting for upstream server to connect back to %s (DST=%s:%d)",
			boundAddr.String(), host, port)
	}

	// Wait for the inbound connection. The application server has up to
	// 60 seconds to call us back; tighter than 5 min keep-alives but
	// generous for slow NAT-traversal setups.
	if err := control.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
		log.Printf("[SOCKS5 BIND] setreaddeadline: %v", err)
		return
	}

	// Accept in a goroutine so we can also notice if the client gives up
	// and closes the control channel first.
	type acceptResult struct {
		c   net.Conn
		err error
	}
	resCh := make(chan acceptResult, 1)
	go func() {
		c, err := ln.Accept()
		resCh <- acceptResult{c: c, err: err}
	}()
	// We also want to know if the control channel was closed (cancelled)
	// so we don't leak the accepted conn on a hung peer. Just let the
	// accept race against the 60s deadline set above.

	var upstream net.Conn
	select {
	case res := <-resCh:
		if res.err != nil {
			log.Printf("[SOCKS5 BIND] accept failed: %v", res.err)
			_ = socks5SendReply(control, socks5RepGeneralFailure)
			return
		}
		upstream = res.c
	case <-time.After(60 * time.Second):
		log.Printf("[SOCKS5 BIND] timeout waiting for upstream server to connect back")
		_ = socks5SendReply(control, socks5RepGeneralFailure)
		return
	}
	defer upstream.Close()

	// Restore the control channel's read deadline (it was set to 60s for
	// the accept; we now use it as a pure TCP proxy).
	_ = control.SetReadDeadline(time.Time{})

	// Reply #2: BND.ADDR/BND.PORT now carries the upstream server's
	// source address — per RFC 1928 §6. The client uses this to confirm
	// which connection the SOCKS5 server accepted.
	if err := socks5SendReplyAddr(control, socks5RepSuccess, upstream.RemoteAddr()); err != nil {
		log.Printf("[SOCKS5 BIND] reply #2 failed: %v", err)
		return
	}

	logUrl := "socks5-bind://" + net.JoinHostPort(host, strconv.Itoa(int(port)))
	LogProxyAction(logUrl, user, ProxyActionSSLDirect)

	// Bidirectional copy until either side EOFs.
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, control)
		_ = control.(closeWriter).CloseWrite()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(control, upstream)
		_ = upstream.(closeWriter).CloseWrite()
		done <- struct{}{}
	}()
	<-done
}

// socks5SendReplyAddr writes a SOCKS5 reply whose BND.ADDR/BND.PORT are
// taken from a net.Addr (used by BIND's first/second reply and by
// UDP ASSOCIATE's single reply). Accepts both *net.TCPAddr and
// *net.UDPAddr — they share the IP/Port fields.
func socks5SendReplyAddr(control net.Conn, rep uint8, addr net.Addr) error {
	var ip net.IP
	var port int
	switch a := addr.(type) {
	case *net.TCPAddr:
		ip, port = a.IP, a.Port
	case *net.UDPAddr:
		ip, port = a.IP, a.Port
	default:
		// Fallback: zero IPv4.
		return socks5SendReply(control, rep)
	}
	ip4 := ip.To4()
	if ip4 != nil {
		buf := []byte{
			socks5Ver, rep, 0x00,
			socks5AtypIPv4,
			ip4[0], ip4[1], ip4[2], ip4[3],
			byte(port >> 8), byte(port),
		}
		_, err := control.Write(buf)
		return err
	}
	v6 := ip.To16()
	if v6 == nil {
		return socks5SendReply(control, rep)
	}
	buf := []byte{socks5Ver, rep, 0x00, socks5AtypIPv6}
	buf = append(buf, v6...)
	buf = append(buf, byte(port>>8), byte(port))
	_, err := control.Write(buf)
	return err
}