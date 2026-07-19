package gatesentryproxy

// SOCKS5 HTTPS MITM path.
//
// When the destination is port 443 and IProxy.DoMitm(host) is true, we
// can't just tunnel TLS — we need to peek the TLS ClientHello the client
// sends, extract the SNI, and either bump (terminate TLS, sign a forged
// cert with Gatesentry's CA, present it to the client, then relay the
// cleartext HTTP layer through Gatesentry's full filter chain) or fall
// back to a plain TCP tunnel.
//
// This file is the SOCKS5 analogue of handleTransparentHTTPS in
// transparent_listener.go:185-274, adapted to the SOCKS5 case where the
// "original destination" comes from the CONNECT request instead of
// SO_ORIGINAL_DST, and where the client conn is the SOCKS5 client conn.
//
// Cross-platform: same package as socks5.go, no kernel syscalls.

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	gsClientHello "bitbucket.org/abdullah_irfan/gatesentryproxy/clienthello"
)

// handleSocks5HTTPSMITM peeks the client's TLS ClientHello from `conn`,
// decides bump-vs-tunnel, and either runs SSLBump (terminate TLS in front
// of the client and relay the cleartext HTTP layer through Gatesentry's
// filter pipeline) or falls back to a plain TCP tunnel.
//
// The SOCKS5 success reply must already have been sent by the caller.
func handleSocks5HTTPSMITM(conn net.Conn, host, user string) {
	serverAddr := net.JoinHostPort(host, "443")
	passthru := NewGSProxyPassthru()

	// Bound the ClientHello read so a misbehaving client can't park us
	// forever. 5s is generous — a real ClientHello is well under 1 KB.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	clientHello, err := gsClientHello.ReadClientHello(conn)
	if err != nil {
		if DebugLogging {
			log.Printf("[SOCKS5] ClientHello read failed for %s: %v, falling back to plain tunnel", serverAddr, err)
		}
		_ = conn.SetReadDeadline(time.Time{})
		if len(clientHello) > 0 {
			// We consumed some bytes — replay them on the tunnel side.
			freshConn := &prependConn{Conn: conn, buf: clientHello, offset: 0}
			LogProxyAction("https://"+host, user, ProxyActionSSLDirect)
			upstream, dialErr := dialUpstream(serverAddr)
			if dialErr != nil {
				LogProxyAction("https://"+host, user, ProxyActionFilterError)
				return
			}
			defer upstream.Close()
			pipeBidirectional(freshConn, upstream)
		} else {
			// Nothing usable — give up.
			LogProxyAction("https://"+host, user, ProxyActionFilterError)
		}
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	// Extract SNI from the ClientHello.
	serverName := ""
	var hello gsClientHello.ClientHello
	if unmarshalErr := hello.Unmarshall(clientHello); unmarshalErr != nil {
		if DebugLogging {
			log.Printf("[SOCKS5] Failed to parse ClientHello for %s: %v", serverAddr, unmarshalErr)
		}
	} else {
		serverName = hello.SNI
	}

	// Re-run the filter chain against the SNI if present (host-level
	// filter already ran on the CONNECT destination, but for HTTPS the
	// host can lie — the SNI is what we actually care about).
	ruleMatchHost := host
	if serverName != "" {
		ruleMatchHost = serverName
	}
	if shouldBlock, _, _ := CheckProxyRules(ruleMatchHost, user); shouldBlock {
		logUrl := "https://" + host
		if serverName != "" {
			logUrl = "https://" + serverName
		}
		LogProxyAction(logUrl, user, ProxyActionBlockedUrl)
		return
	}
	if IProxy != nil && IProxy.UrlAccessHandler != nil {
		ud := &GSUrlFilterData{Url: "https://" + ruleMatchHost, User: user}
		IProxy.UrlAccessHandler(ud)
		if ud.FilterResponseAction == ProxyActionBlockedUrl {
			LogProxyAction("https://"+ruleMatchHost, user, ProxyActionBlockedUrl)
			return
		}
	}

	// Re-check DoMitm against the SNI (DoMitm at CONNECT time used the
	// destination host; for HTTPS the SNI is the actual target).
	mitmCheckHost := serverAddr
	if serverName != "" {
		mitmCheckHost = net.JoinHostPort(serverName, "443")
	}
	decision := socks5Decision(mitmCheckHost)
	if decision.ShouldBlock {
		logUrl := "https://" + host
		if serverName != "" {
			logUrl = "https://" + serverName
		}
		LogProxyAction(logUrl, user, ProxyActionBlockedUrl)
		sendBlockMessageOverConn(conn, decision.BlockPage)
		return
	}
	shouldMitm := decision.ShouldMITM
	if !shouldMitm {
		// Don't bump — replay ClientHello and tunnel.
		logUrl := "https://" + host
		if serverName != "" {
			logUrl = "https://" + serverName
		}
		LogProxyAction(logUrl, user, ProxyActionSSLDirect)
		freshConn := &prependConn{Conn: conn, buf: clientHello, offset: 0}
		upstream, dialErr := dialUpstream(serverAddr)
		if dialErr != nil {
			LogProxyAction(logUrl, user, ProxyActionFilterError)
			return
		}
		defer upstream.Close()
		pipeBidirectional(freshConn, upstream)
		return
	}

	// Bump: run SSLBump on the client conn. SSLBump handles the upstream
	// dial, cert signing, TLS handshake with the client, and serves the
	// cleartext HTTP layer through the existing ProxyHandler — which
	// re-runs UrlAccess / ContentHandler / ContentTypeHandler / etc.
	if DebugLogging {
		log.Printf("[SOCKS5] Performing SSL Bump for %s (SNI: %s)", serverAddr, serverName)
	}
	SSLBump(conn, serverAddr, user, "", nil, passthru, IProxy, clientHello)
}

// dialUpstream opens a TCP connection to addr via DialUpstream, which
// honours the configured UpstreamDialer (e.g. an egress_socks5 SOCKS5
// proxy) when set, otherwise dials directly with conservative timeouts.
// Used by both the fallback tunnel and the passthrough-ClientHello path.
func dialUpstream(addr string) (net.Conn, error) {
	c, err := DialUpstream(context.Background(), "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("socks5: dial %s: %w", addr, err)
	}
	return c, nil
}

// pipeBidirectional is a small io.Copy helper used by both tunnel paths.
// Closes both ends when either direction hits EOF.
func pipeBidirectional(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(b, a)
		_ = b.(closeWriter).CloseWrite()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(a, b)
		_ = a.(closeWriter).CloseWrite()
		done <- struct{}{}
	}()
	<-done
}

// closeWriter is the subset of net.TCPConn we use for half-close. Asserted
// in pipeBidirectional; the dynamic type will fail and be ignored if the
// conn doesn't support CloseWrite (e.g. in-memory test conns).
type closeWriter interface {
	CloseWrite() error
}
