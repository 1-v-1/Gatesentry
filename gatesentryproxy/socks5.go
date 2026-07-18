package gatesentryproxy

// SOCKS5 proxy listener.
//
// We implement the SOCKS5 CONNECT framing ourselves (instead of depending on
// github.com/armon/go-socks5) so that we have full control over the byte
// stream — required for HTTPS MITM, where we must peek the TLS ClientHello
// the client sends AFTER the SOCKS5 handshake and BEFORE forwarding bytes.
//
// The listener supports two connection kinds:
//
//   - HTTP / plain TCP CONNECT (any port): the conn is dialeed upstream and
//     bytes are io.Copy'd in both directions. This is the v1 behaviour.
//
//   - HTTPS CONNECT (port 443) when IProxy.DoMitm(host) is true: the client's
//     TLS ClientHello is peeked, the SNI is extracted, the rules/filters run
//     a second time against the SNI, and SSLBump terminates TLS so Gatesentry
//     can inspect the decrypted HTTP layer (text filter, content-type filter,
//     rules, etc.) — same as the transparent HTTPS listener does.
//
// The full filter chain runs at SOCKS5-connect time against the destination
// host (UserAccess → TimeAccess → UrlAccess → RuleMatch → IsExceptionUrl).
// For HTTPS targets that pass, an additional SNI-based rule check runs after
// the ClientHello peek, matching what handleTransparentHTTPS does.

import (
	"encoding/binary"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync/atomic"
	"time"
)

// ---- Package-level state (mirrors transparent_listener.go) ----

var (
	socks5Enabled  = true
	socks5Port     = 10415
	socks5Running  atomic.Bool
	socks5Listener net.Listener
)

func IsSocks5Enabled() bool   { return socks5Enabled }
func SetSocks5Enabled(b bool) { socks5Enabled = b }
func GetSocks5Port() int      { return socks5Port }
func SetSocks5Port(p int)     { socks5Port = p }
func IsSocks5Running() bool   { return socks5Running.Load() }

// SOCKS5 protocol constants.
const (
	socks5Ver              = 0x05
	socks5AuthNoAuth       = 0x00
	socks5AuthMethodUserPass = 0x02
	socks5AuthNoAcceptable = 0xFF
	socks5CmdConnect       = 0x01
	socks5AtypIPv4         = 0x01
	socks5AtypDomain       = 0x03
	socks5AtypIPv6         = 0x04
	socks5RepSuccess       = 0x00
	socks5RepGeneralFailure = 0x01
	socks5RepConnRefused    = 0x05
	socks5RepCmdNotSupported = 0x07
	socks5RepAddrNotSupported = 0x08
)

// ---- Auth: validate SOCKS5 user/pass against R.AuthUsers ----

// socks5ValidateCreds validates a (user, pass) tuple from the SOCKS5 RFC 1929
// subnegotiation against R.AuthUsers. The user/pass comes in cleartext from
// the client; we reconstruct the "Basic <b64>" header that R.IsUserValid
// already understands, so no user-model changes are needed.
func socks5ValidateCreds(user, pass string) bool {
	if IProxy == nil {
		return false
	}
	if IProxy.IsAuthEnabled != nil && !IProxy.IsAuthEnabled() {
		return true
	}
	if IProxy.AuthHandler == nil {
		return false
	}
	raw := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	return IProxy.AuthHandler(raw)
}

// ---- Filter evaluation: shared between CONNECT and HTTPS paths ----

// socks5EvalFilters runs the full Gatesentry filter chain against the
// destination host. Returns true if the CONNECT should proceed. On a false
// return, the caller should emit a SOCKS5 failure reply.
//
// This is the same evaluation gsRuleSet.Allow did in v1 — extracted into a
// plain function so both the CONNECT framing code and the HTTPS MITM path
// can share it without an interface dependency.
func socks5EvalFilters(host, user, urlStr string) bool {
	if IProxy == nil {
		log.Printf("[SOCKS5] filter: IProxy nil — denying %s", urlStr)
		return false
	}
	if DebugLogging {
		log.Printf("[SOCKS5] filter: evaluating %s for user=%q", urlStr, user)
	}
	// 1. User access (is the user blocked from internet?)
	if IProxy.UserAccessHandler != nil {
		ud := &GSUserAccessFilterData{User: user}
		IProxy.UserAccessHandler(ud)
		if DebugLogging {
			log.Printf("[SOCKS5] filter: UserAccessHandler action=%q", ud.FilterResponseAction)
		}
		if ud.FilterResponseAction == ProxyActionBlockedInternetForUser {
			LogProxyAction(urlStr, user, ProxyActionBlockedInternetForUser)
			return false
		}
	}
	// 2. Time-of-day access (configured block windows)
	if IProxy.TimeAccessHandler != nil {
		td := &GSTimeAccessFilterData{Url: urlStr, User: user}
		IProxy.TimeAccessHandler(td)
		if DebugLogging {
			log.Printf("[SOCKS5] filter: TimeAccessHandler action=%q", td.FilterResponseAction)
		}
		if td.FilterResponseAction == string(ProxyActionBlockedTime) {
			LogProxyAction(urlStr, user, ProxyActionBlockedTime)
			return false
		}
	}
	// 3. URL filter (configured URL block lists, e.g. blockedsites.json)
	if IProxy.UrlAccessHandler != nil {
		ud := &GSUrlFilterData{Url: urlStr, User: user}
		IProxy.UrlAccessHandler(ud)
		if DebugLogging {
			log.Printf("[SOCKS5] filter: UrlAccessHandler action=%q", ud.FilterResponseAction)
		}
		if ud.FilterResponseAction == ProxyActionBlockedUrl {
			LogProxyAction(urlStr, user, ProxyActionBlockedUrl)
			return false
		}
	}
	// 4. Rule manager (web-admin-defined rules with priority + time window)
	if shouldBlock, _, _ := CheckProxyRules(host, user); shouldBlock {
		log.Printf("[SOCKS5] filter: CheckProxyRules BLOCKED %s user=%q", host, user)
		LogProxyAction(urlStr, user, ProxyActionBlockedUrl)
		return false
	}
	// 5. Whitelist — already permissive above, but call the hook for future
	// extensions.
	_ = IProxy.IsExceptionUrl
	return true
}

// socks5ShouldMitm returns true if HTTPS MITM is enabled and the host should
// be bumped. Mirrors the decision in handleTransparentHTTPS.
func socks5ShouldMitm(host string) bool {
	if IProxy == nil || IProxy.DoMitm == nil {
		return false
	}
	return IProxy.DoMitm(host)
}

// ---- SOCKS5 framing ----

// socks5ReadGreeting reads the SOCKS5 greeting (VER, NAUTH, METHODS) and
// returns the chosen auth method. Returns 0xFF if no acceptable method.
func socks5ReadGreeting(conn net.Conn) (uint8, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, err
	}
	if header[0] != socks5Ver {
		return 0, fmt.Errorf("socks5: unsupported version %d", header[0])
	}
	nauth := int(header[1])
	if nauth == 0 {
		return 0, fmt.Errorf("socks5: zero auth methods")
	}
	methods := make([]byte, nauth)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return 0, err
	}
	authEnabled := IProxy != nil && IProxy.IsAuthEnabled != nil && IProxy.IsAuthEnabled()
	// Pick the only method that makes sense given the server's auth state.
	// Don't fall back across modes — that would silently reject clients
	// sending only NoAuth when auth is enabled (and vice versa).
	var want uint8 = socks5AuthNoAuth
	if authEnabled {
		want = socks5AuthMethodUserPass
	}
	for _, m := range methods {
		if m == want {
			return want, nil
		}
	}
	return socks5AuthNoAcceptable, nil
}

// socks5SendGreetingReply sends the method-selection reply.
func socks5SendGreetingReply(conn net.Conn, method uint8) error {
	_, err := conn.Write([]byte{socks5Ver, method})
	return err
}

// socks5DoAuthUserPass implements the RFC 1929 username/password subnegotiation.
// Writes 01 STATUS at the end (00 = success, 01 = failure).
// On success returns (user, nil). On failure returns ("", err).
func socks5DoAuthUserPass(conn net.Conn) (string, error) {
	ver := make([]byte, 1)
	if _, err := io.ReadFull(conn, ver); err != nil {
		return "", err
	}
	if ver[0] != 0x01 {
		return "", fmt.Errorf("socks5 userpass: unsupported subnegotiation version %d", ver[0])
	}
	ulenByte := make([]byte, 1)
	if _, err := io.ReadFull(conn, ulenByte); err != nil {
		return "", err
	}
	ulen := int(ulenByte[0])
	uname := make([]byte, ulen)
	if _, err := io.ReadFull(conn, uname); err != nil {
		return "", err
	}
	plenByte := make([]byte, 1)
	if _, err := io.ReadFull(conn, plenByte); err != nil {
		return "", err
	}
	plen := int(plenByte[0])
	pass := make([]byte, plen)
	if _, err := io.ReadFull(conn, pass); err != nil {
		return "", err
	}
	user := string(uname)
	ok := socks5ValidateCreds(user, string(pass))
	status := byte(0x00)
	if !ok {
		status = 0x01
	}
	if _, err := conn.Write([]byte{0x01, status}); err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("socks5 userpass: auth failed for user=%q", user)
	}
	return user, nil
}

// socks5AddrSpec mirrors AddrSpec from the SOCKS5 spec.
type socks5AddrSpec struct {
	Host string // FQDN for domain types, IPv4/IPv6 string otherwise
	Port uint16
}

// socks5ReadRequest reads VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT. Returns
// the parsed request, or an error.
func socks5ReadRequest(conn net.Conn) (cmd uint8, addr socks5AddrSpec, err error) {
	header := make([]byte, 4)
	if _, err = io.ReadFull(conn, header); err != nil {
		return 0, socks5AddrSpec{}, err
	}
	if header[0] != socks5Ver {
		return 0, socks5AddrSpec{}, fmt.Errorf("socks5 request: unsupported version %d", header[0])
	}
	cmd = header[1]
	switch header[3] {
	case socks5AtypIPv4:
		ip := make([]byte, 4)
		if _, err = io.ReadFull(conn, ip); err != nil {
			return 0, socks5AddrSpec{}, err
		}
		addr.Host = net.IP(ip).String()
	case socks5AtypIPv6:
		ip := make([]byte, 16)
		if _, err = io.ReadFull(conn, ip); err != nil {
			return 0, socks5AddrSpec{}, err
		}
		addr.Host = net.IP(ip).String()
	case socks5AtypDomain:
		lenByte := make([]byte, 1)
		if _, err = io.ReadFull(conn, lenByte); err != nil {
			return 0, socks5AddrSpec{}, err
		}
		domain := make([]byte, int(lenByte[0]))
		if _, err = io.ReadFull(conn, domain); err != nil {
			return 0, socks5AddrSpec{}, err
		}
		addr.Host = string(domain)
	default:
		return 0, socks5AddrSpec{}, fmt.Errorf("socks5 request: unsupported ATYP %d", header[3])
	}
	portBytes := make([]byte, 2)
	if _, err = io.ReadFull(conn, portBytes); err != nil {
		return 0, socks5AddrSpec{}, err
	}
	addr.Port = binary.BigEndian.Uint16(portBytes)
	return cmd, addr, nil
}

// socks5SendReply writes a SOCKS5 reply with the given REP code.
// BND.ADDR/BND.PORT are zero — clients only care about the REP byte.
func socks5SendReply(conn net.Conn, rep uint8) error {
	_, err := conn.Write([]byte{
		socks5Ver, rep, 0x00,
		socks5AtypIPv4,
		0, 0, 0, 0, // BND.ADDR = 0.0.0.0
		0, 0, // BND.PORT = 0
	})
	return err
}

// ---- Connection handler ----

// handleSocks5Conn processes a single SOCKS5 client connection: greeting,
// auth, request, filter chain, and dispatch to the appropriate upstream
// handler (HTTPS MITM or plain TCP tunnel).
func handleSocks5Conn(conn net.Conn) {
	defer conn.Close()

	// 1. Greeting.
	method, err := socks5ReadGreeting(conn)
	if err != nil {
		log.Printf("[SOCKS5] greeting error: %v", err)
		return
	}
	if method == socks5AuthNoAcceptable {
		_ = socks5SendGreetingReply(conn, socks5AuthNoAcceptable)
		return
	}
	if err := socks5SendGreetingReply(conn, method); err != nil {
		return
	}

	// 2. Auth subnegotiation.
	var user string
	if method == socks5AuthMethodUserPass {
		user, err = socks5DoAuthUserPass(conn)
		if err != nil {
			log.Printf("[SOCKS5] auth error: %v", err)
			return
		}
	}

	// 3. Request.
	cmd, addr, err := socks5ReadRequest(conn)
	if err != nil {
		log.Printf("[SOCKS5] request error: %v", err)
		return
	}
	if cmd != socks5CmdConnect {
		LogProxyAction("socks5://(unsupported-cmd)", user, ProxyActionBlockedUrl)
		_ = socks5SendReply(conn, socks5RepCmdNotSupported)
		return
	}

	// 4. Filter chain (host-level). For HTTPS targets we re-run against the
	// SNI after the ClientHello peek; for plain CONNECT this is the only
	// filter pass.
	host := addr.Host
	urlStr := "socks5://" + net.JoinHostPort(host, strconv.Itoa(int(addr.Port)))
	if !socks5EvalFilters(host, user, urlStr) {
		_ = socks5SendReply(conn, socks5RepConnRefused)
		return
	}

	// 5. Dispatch.
	if addr.Port == 443 && socks5ShouldMitm(host) {
		// HTTPS with MITM enabled for this host. Send the SOCKS5 success
		// reply first so the client starts the TLS handshake, then run the
		// MITM flow (ClientHello peek → SSLBump).
		if err := socks5SendReply(conn, socks5RepSuccess); err != nil {
			return
		}
		handleSocks5HTTPSMITM(conn, host, user)
		return
	}

	// Plain TCP tunnel.
	if err := socks5SendReply(conn, socks5RepSuccess); err != nil {
		return
	}
	handleSocks5PlainTunnel(conn, host, addr.Port, user)
}

// handleSocks5PlainTunnel dials the upstream and copies bytes in both
// directions. This is the v1 behaviour, kept for non-443 targets and for
// 443 targets where HTTPS MITM is disabled.
func handleSocks5PlainTunnel(conn net.Conn, host string, port uint16, user string) {
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	d := net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	upstream, err := d.Dial("tcp", addr)
	if err != nil {
		LogProxyAction("socks5://"+addr, user, ProxyActionFilterError)
		return
	}
	defer upstream.Close()

	// Best-effort log on tunnel establishment.
	LogProxyAction("socks5://"+addr, user, ProxyActionSSLDirect)

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, conn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, upstream)
		done <- struct{}{}
	}()
	<-done
}

// ---- Server lifecycle ----

// ResolveSocks5Addr returns the listen address for the SOCKS5 listener.
func ResolveSocks5Addr(envPort string) string {
	port := socks5Port
	if envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil && p > 0 && p <= 65535 {
			port = p
			socks5Port = p
		}
	}
	return "0.0.0.0:" + strconv.Itoa(port)
}

// StartSocks5Server binds a TCP listener and serves on it. Each connection
// is handled in its own goroutine. Returns nil after the listener is bound;
// the goroutine then loops forever.
func StartSocks5Server(addr string) error {
	if !socks5Enabled {
		log.Printf("[SOCKS5] Disabled by configuration; not starting.")
		return nil
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("socks5: failed to bind %s: %w", addr, err)
	}
	socks5Listener = ln
	socks5Running.Store(true)
	log.Printf("[SOCKS5] Listening on %s", addr)

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if socks5Running.Load() {
					log.Printf("[SOCKS5] Accept error: %v", err)
				}
				return
			}
			go handleSocks5Conn(c)
		}
	}()
	return nil
}

// StopSocks5Server closes the listener; in-flight connections keep running.
func StopSocks5Server() error {
	socks5Running.Store(false)
	if socks5Listener != nil {
		err := socks5Listener.Close()
		socks5Listener = nil
		return err
	}
	return nil
}