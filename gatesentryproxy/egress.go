package gatesentryproxy

// Egress HTTP client for Gatesentry's own outbound calls.
//
// gatesentryproxy makes outbound HTTP calls for one thing in the proxy
// code path: AIA (Authority Information Access) cert chain fetching
// during TLS MITM, in certificates.go. We honour the same `egress_socks5`
// runtime setting as the application module does, so an admin who routes
// Gatesentry's egress through a SOCKS5 proxy also gets AIA fetches
// through that same proxy.
//
// The application module owns the setting (it's in the buntdb-backed
// GSSettings store). main.go reads it once at startup and pushes the
// resulting *http.Client into this package via SetEgressHTTPClient.
// gatesentryproxy then uses EgressHTTPClient() wherever it makes an
// outbound HTTP call (currently only AIA fetching).
//
// When no client has been set, we fall back to http.DefaultClient —
// matching the pre-feature behaviour.

import "net/http"

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