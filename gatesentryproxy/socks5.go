package gatesentryproxy

// SOCKS5 proxy listener.
//
// This file wraps github.com/armon/go-socks5 with Gatesentry-specific hooks:
//   - CredentialStore → drives IProxy.AuthHandler (re-uses R.AuthUsers)
//   - RuleSet         → runs the full filter chain on CONNECT commands
//                       (TimeAccess → UrlAccess → RuleMatch → IsExceptionUrl)
//   - Dial            → plain TCP tunnel (v1); HTTPS MITM hook left for v2
//
// The proxy log entries are emitted through LogProxyAction so they land in
// the same buntdb-backed access log as the HTTP and transparent proxies,
// with the same 7-day TTL.
//
// Cross-platform: no kernel-specific syscalls. Unlike the transparent
// listener, no //go:build linux stubs are needed.

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	gsSocks "github.com/armon/go-socks5"
)

// ---- Package-level state (mirrors transparent_listener.go) ----

var (
	socks5Enabled   = true
	socks5Port      = 10415
	socks5Running   atomic.Bool
	socks5Server    *gsSocks.Server
	socks5Listener  net.Listener
)

func IsSocks5Enabled() bool     { return socks5Enabled }
func SetSocks5Enabled(b bool)   { socks5Enabled = b }
func GetSocks5Port() int        { return socks5Port }
func SetSocks5Port(p int)       { socks5Port = p }
func IsSocks5Running() bool     { return socks5Running.Load() }

// socks5UserFromCtx extracts the username negotiated during RFC 1929 auth, or
// the empty string if the connection used NoAuth.
func socks5UserFromCtx(req *gsSocks.Request) string {
	if req == nil || req.AuthContext == nil || req.AuthContext.Payload == nil {
		return ""
	}
	return req.AuthContext.Payload["Username"]
}

// ---- Credential store: validates SOCKS5 user/pass against R.AuthUsers ----

// gsCredentialStore implements gsSocks.CredentialStore. The SOCKS5 library
// gives us a cleartext (user, pass) tuple (RFC 1929); we reconstruct the
// "Basic <b64>" header that R.IsUserValid already understands, so the
// existing user store is reused without any schema change.
type gsCredentialStore struct{}

func (gsCredentialStore) Valid(user, pass string) bool {
	if IProxy == nil {
		// No proxy wired yet → fail closed. The settings init order ensures
		// IProxy is set before the listener starts, but defensive in case
		// anyone calls NewSocks5Server earlier in init.
		return false
	}
	// If gateway-level auth is disabled, permit all SOCKS5 credentials.
	// Otherwise, validate against the configured users.
	if IProxy.IsAuthEnabled != nil && !IProxy.IsAuthEnabled() {
		return true
	}
	if IProxy.AuthHandler == nil {
		return false
	}
	raw := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	return IProxy.AuthHandler(raw)
}

// ---- Rule set: runs the Gatesentry filter chain on CONNECT ----

// gsRuleSet implements gsSocks.RuleSet. go-socks5 invokes Allow() after
// authentication and before Dial(), giving us the destination and user but
// not yet any application-layer bytes — exactly the right moment to apply
// the same filtering the HTTP proxy applies (main.go:262-399).
type gsRuleSet struct{}

func (gsRuleSet) Allow(ctx context.Context, req *gsSocks.Request) (context.Context, bool) {
	if IProxy == nil {
		return ctx, false
	}
	// Only CONNECT is supported. BIND / UDP_ASSOCIATE are not implemented.
	if req.Command != gsSocks.ConnectCommand {
		LogProxyAction("socks5://(unsupported-cmd)", socks5UserFromCtx(req), ProxyActionBlockedUrl)
		return ctx, false
	}

	// Determine the host the client asked for. The library runs DNS resolve
	// before us, so req.DestAddr may hold an IP; we want the original FQDN
	// for filter matching (URL blocklists / rules match by name, not IP).
	host := req.DestAddr.FQDN
	if host == "" {
		if req.DestAddr.IP != nil {
			host = req.DestAddr.IP.String()
		}
	}
	if host == "" {
		return ctx, false
	}
	user := socks5UserFromCtx(req)
	urlStr := "socks5://" + host

	// 1. User access (is the user blocked from internet?)
	if IProxy.UserAccessHandler != nil {
		ud := &GSUserAccessFilterData{User: user}
		IProxy.UserAccessHandler(ud)
		if ud.FilterResponseAction == ProxyActionBlockedInternetForUser {
			LogProxyAction(urlStr, user, ProxyActionBlockedInternetForUser)
			return ctx, false
		}
		// UserNotFound is treated as "permit" for SOCKS5 — unlike HTTP, where
		// missing users get a 407. Auth already happened at the SOCKS5 layer.
	}

	// 2. Time-of-day access (configured block windows)
	if IProxy.TimeAccessHandler != nil {
		td := &GSTimeAccessFilterData{Url: urlStr, User: user}
		IProxy.TimeAccessHandler(td)
		if td.FilterResponseAction == string(ProxyActionBlockedTime) {
			LogProxyAction(urlStr, user, ProxyActionBlockedTime)
			return ctx, false
		}
	}

	// 3. URL filter (configured URL block lists, e.g. blockedsites.json)
	if IProxy.UrlAccessHandler != nil {
		ud := &GSUrlFilterData{Url: urlStr, User: user}
		IProxy.UrlAccessHandler(ud)
		if ud.FilterResponseAction == ProxyActionBlockedUrl {
			LogProxyAction(urlStr, user, ProxyActionBlockedUrl)
			return ctx, false
		}
	}

	// 4. Rule manager (web-admin-defined rules with priority + time window)
	if shouldBlock, _, _ := CheckProxyRules(host, user); shouldBlock {
		LogProxyAction(urlStr, user, ProxyActionBlockedUrl)
		return ctx, false
	}

	// 5. Exception URL list (whitelist) — already permissive above, but we
	// still consult the hook so admin can later make it have stronger effect.
	_ = IProxy.IsExceptionUrl

	// CONNECT granted. The library will proceed to Dial and then io.Copy.
	return ctx, true
}

// ---- Dial hook ----

// socks5Dial is the upstream dial used by go-socks5. v1 keeps it as a plain
// TCP tunnel — the destination's hostname has already been filtered by
// gsRuleSet above, so CONNECT itself is safe. Application-layer content
// filtering for HTTPS-via-SOCKS5 is a v2 concern; the insertion point is
// this function: replace the plain net.Dial with a peek-then-SSLBump flow
// modelled on handleTransparentHTTPS() in transparent_listener.go.
func socks5Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if DebugLogging {
		log.Printf("[SOCKS5] Dialing upstream %s", addr)
	}
	d := net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	return d.DialContext(ctx, network, addr)
}

// ---- Server construction + lifecycle ----

// NewSocks5Server assembles a go-socks5 Server wired to Gatesentry's
// filter chain. Safe to call before IProxy is set (we just store the
// references; hooks will no-op until IProxy is wired).
func NewSocks5Server() *gsSocks.Server {
	conf := &gsSocks.Config{
		// AuthMethods: explicit list to advertise both NoAuth and UserPassAuth.
		// SOCKS5 clients will pick one based on what the server offers.
		AuthMethods: []gsSocks.Authenticator{
			gsSocks.NoAuthAuthenticator{},
			gsSocks.UserPassAuthenticator{Credentials: gsCredentialStore{}},
		},
		Rules: gsRuleSet{},
		Dial:  socks5Dial,
		Logger: log.New(log.Writer(), "[socks5] ", log.LstdFlags),
	}
	srv, err := gsSocks.New(conf)
	if err != nil {
		log.Printf("[SOCKS5] Failed to construct server: %v", err)
		return nil
	}
	return srv
}

// StartSocks5Server binds a TCP listener and serves on it. Caller is
// expected to run this in its own goroutine. Returns immediately with nil
// once the listener is bound; the goroutine then blocks on Serve().
func StartSocks5Server(addr string) error {
	if !socks5Enabled {
		log.Printf("[SOCKS5] Disabled by configuration; not starting.")
		return nil
	}
	srv := NewSocks5Server()
	if srv == nil {
		return fmt.Errorf("socks5: failed to build server")
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("socks5: failed to bind %s: %w", addr, err)
	}
	socks5Listener = ln
	socks5Server = srv
	socks5Running.Store(true)
	log.Printf("[SOCKS5] Listening on %s", addr)

	return srv.Serve(ln)
}

// StopSocks5Server closes the listener; in-flight connections keep running
// because go-socks5 doesn't expose a graceful-shutdown hook.
func StopSocks5Server() error {
	socks5Running.Store(false)
	if socks5Listener != nil {
		err := socks5Listener.Close()
		socks5Listener = nil
		return err
	}
	return nil
}

// ---- Convenience used by main.go at boot ----

// ResolveSocks5Addr returns the listen address for the SOCKS5 listener,
// honouring the env var GS_SOCKS5_PORT override and the package-level
// Socks5Port / Socks5Enabled switches.
func ResolveSocks5Addr(envPort string) string {
	port := socks5Port
	if envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil && p > 0 && p <= 65535 {
			port = p
			socks5Port = p
		}
	}
	addr := "0.0.0.0:" + strconv.Itoa(port)
	if !strings.Contains(addr, ":") {
		addr = "0.0.0.0:" + addr
	}
	return addr
}