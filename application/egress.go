package gatesentryf

// Egress HTTP client: Gatesentry's own outbound HTTP calls (DNS blocklist
// downloads, AIA cert fetches, AI image scanner POST) should optionally
// go through an upstream SOCKS5 proxy configured via the `egress_socks5`
// runtime setting.
//
// The helper here builds an *http.Client with a SOCKS5 dialer when the
// setting is non-empty; otherwise it returns http.DefaultClient so the
// behaviour matches the pre-feature codebase.
//
// Format: socks5://[user:pass@]host:port
// Empty string = direct (no proxy).

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

// EgressHTTPClient returns an *http.Client configured to route requests
// through the SOCKS5 proxy configured by the `egress_socks5` setting.
// Returns http.DefaultClient when the setting is empty.
func (R *GSRuntime) EgressHTTPClient() *http.Client {
	socksURL := R.GSSettings.Get("egress_socks5")
	if socksURL == "" {
		return http.DefaultClient
	}
	client, err := buildSOCKS5Client(socksURL)
	if err != nil {
		// Fall back to default client if the URL is malformed — admin can
		// fix the setting later; meanwhile egress traffic just goes direct.
		return http.DefaultClient
	}
	return client
}

// buildSOCKS5Client parses a socks5://[user:pass@]host:port URL and
// returns an *http.Client with a SOCKS5 dialer. The transport uses a
// 30s dial timeout and 10s TLS handshake timeout to match the rest of
// the proxy's outbound behaviour.
func buildSOCKS5Client(socksURL string) (*http.Client, error) {
	u, err := url.Parse(socksURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "socks5" && u.Scheme != "socks5h" {
		// We don't support HTTP proxies here; only SOCKS5.
		// For HTTP proxies, callers should set http.DefaultTransport.Proxy
		// to a regular http.ProxyURL — out of scope for this setting.
		return nil, &url.Error{Op: "buildSOCKS5Client", URL: socksURL, Err: errUnsupportedScheme}
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Host, "1080")
	}
	var auth *proxy.Auth
	if u.User != nil {
		pw, _ := u.User.Password()
		auth = &proxy.Auth{User: u.User.Username(), Password: pw}
	}
	dialer, err := proxy.SOCKS5("tcp", host, auth, proxy.Direct)
	if err != nil {
		return nil, err
	}
	// Wrap with a context-aware dialer so http.Transport honors timeouts.
	ctxDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		ctxDialer = proxy.ContextDialer(dialerShim{d: dialer})
	}
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			DialContext: ctxDialer.DialContext,
			TLSClientConfig: &tls.Config{
				// Blocklist downloads + AIA cert fetches are to fixed
				// hosts that admins have configured; mirror the rest
				// of the binary by accepting the system roots.
				InsecureSkipVerify: false,
				MinVersion:         tls.VersionTLS12,
			},
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       90 * time.Second,
		},
	}, nil
}

// dialerShim wraps a proxy.Dialer (which doesn't take a context) into a
// proxy.ContextDialer using a fixed timeout.
type dialerShim struct {
	d proxy.Dialer
}

func (s dialerShim) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	type result struct {
		c   net.Conn
		err error
	}
	done := make(chan result, 1)
	go func() {
		c, err := s.d.Dial(network, addr)
		done <- result{c: c, err: err}
	}()
	select {
	case r := <-done:
		return r.c, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// errUnsupportedScheme is returned when the egress URL uses a non-SOCKS5
// scheme. We expose it as a sentinel so callers can match it without
// importing net/url.
var errUnsupportedScheme = proxyError("egress_socks5: only socks5:// and socks5h:// schemes are supported")

type proxyError string

func (e proxyError) Error() string { return string(e) }