package gatesentryproxy

// Egress HTTP client + Upstream dialer for Gatesentry's own outbound
// calls.
//
// Two related-but-distinct egress paths:
//
//  1. EgressHTTPClient: outbound HTTP calls in the proxy code path
//     (currently only AIA cert chain fetching during TLS MITM). Used
//     for one-shot HTTP requests.
//
//  2. UpstreamDialer: the net.Dialer-style function used for ALL
//     outbound TCP connections that originate from the proxy listeners
//     themselves — CONNECT forward, SSLBump upstream dial, SOCKS5
//     plain tunnel, transparent HTTPS handler, etc. When the admin
//     sets `egress_socks5`, every byte that leaves Gatesentry on
//     behalf of a client flows through that upstream SOCKS5 first.
//
// The application module owns the settings (buntdb-backed GSSettings
// store). main.go reads `egress_socks5` once at startup and pushes
// the resulting *http.Client and dialer function into this package
// via SetEgressHTTPClient and SetUpstreamDialer.
//
// When no client / dialer has been set, both fall back to the
// pre-feature behaviour (http.DefaultClient, direct net.Dialer).

import (
	"context"
	"net"
	"net/http"
	"time"
)

var egressHTTPClient *http.Client

// SetEgressHTTPClient installs the *http.Client that all egress HTTP
// calls in gatesentryproxy should use. Called from main.go after the
// application runtime has read the egress_socks5 setting. Pass nil to
// reset to http.DefaultClient.
func SetEgressHTTPClient(client *http.Client) {
	egressHTTPClient = client
}

// EgressHTTPClient returns the configured egress client, or
// http.DefaultClient if none has been installed.
func EgressHTTPClient() *http.Client {
	if egressHTTPClient == nil {
		return http.DefaultClient
	}
	return egressHTTPClient
}

// UpstreamDialer is the function used for all outbound TCP connections
// in the proxy code path. When unset, DialUpstream falls back to a
// direct *net.Dialer with reasonable timeouts.
//
// main.go installs a SOCKS5-aware dialer when `egress_socks5` is set.
var UpstreamDialer func(ctx context.Context, network, addr string) (net.Conn, error)

// SetUpstreamDialer installs the dialer used for all outbound TCP
// connections in the proxy. Pass nil to reset to direct dial.
func SetUpstreamDialer(d func(ctx context.Context, network, addr string) (net.Conn, error)) {
	UpstreamDialer = d
}

// DialUpstream is the canonical entry point for any outbound TCP
// connection in the proxy. It honours the configured UpstreamDialer
// when set, otherwise dials directly with a 30s timeout.
func DialUpstream(ctx context.Context, network, addr string) (net.Conn, error) {
	if UpstreamDialer != nil {
		return UpstreamDialer(ctx, network, addr)
	}
	var d net.Dialer
	d.Timeout = 30 * time.Second
	d.KeepAlive = 30 * time.Second
	return d.DialContext(ctx, network, addr)
}

// soks5Dialer is a *net.Dialer whose DialContext method delegates
// to the configured UpstreamDialer. Method shadowing on the embedded
// *net.Dialer makes DialContext take precedence over the default
// implementation.
//
// http.Transport.Dial and tls.DialWithDialer both call .DialContext on
// the *net.Dialer they receive, so passing *soks5Dialer makes the
// SOCKS5 path active for any code that goes through those APIs.
type soks5Dialer struct {
	*net.Dialer
}

func (d *soks5Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return DialUpstream(ctx, network, addr)
}

// NewUpstreamContextDialer returns a *net.Dialer that uses the
// configured UpstreamDialer. Pass to http.Transport.Dial or
// tls.DialWithDialer.
func NewUpstreamContextDialer() *net.Dialer {
	d := &soks5Dialer{
		Dialer: &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second},
	}
	// Returning *net.Dialer (not *soks5Dialer) keeps the call site
	// generic, but the method dispatch still routes to soks5Dialer.
	return d.Dialer
}