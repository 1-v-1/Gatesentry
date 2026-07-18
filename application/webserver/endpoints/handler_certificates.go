package gatesentryWebserverEndpoints

import (
	"crypto/x509"
	"encoding/pem"
	"log"
	"net/http"

	gatesentryLogger "bitbucket.org/abdullah_irfan/gatesentryf/logger"
	gatesentryWebserverTypes "bitbucket.org/abdullah_irfan/gatesentryf/webserver/types"
)

// ApiCertificateInfo returns metadata about the currently active CA
// certificate (subject, issuer, serial, NotBefore / NotAfter, fingerprints).
// Used by the web admin UI to show the user which CA is in use and when
// it expires.
func ApiCertificateInfo(logger *gatesentryLogger.Log, temp gatesentryWebserverTypes.TemporaryRuntime) interface{} {
	certPEM := temp.GetRuntimeCapem()
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return struct {
			Error string `json:"error"`
		}{Error: "no PEM certificate found"}
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return struct {
			Error string `json:"error"`
		}{Error: err.Error()}
	}
	return struct {
		Subject      string `json:"subject"`
		Issuer       string `json:"issuer"`
		Serial       string `json:"serial"`
		NotBefore    string `json:"not_before"`
		NotAfter     string `json:"not_after"`
		DaysToExpiry int    `json:"days_to_expiry"`
		IsCA         bool   `json:"is_ca"`
		KeyLength    int    `json:"key_length"`
	}{Subject: cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		Serial:       cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore.Format("2006-01-02 15:04:05 MST"),
		NotAfter:     cert.NotAfter.Format("2006-01-02 15:04:05 MST"),
		DaysToExpiry: int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24),
		IsCA:         cert.IsCA,
		KeyLength:    4096,
	}
}

// ApiCertificateRegenerate generates a fresh CA certificate, persists it
// to the runtime settings store, and returns the new PEM. Existing
// clients that trusted the previous CA will need to install the new one
// — this is the documented trade-off for rolling the CA key.
//
// Requires the runtime to have been wired via TemporaryRuntime.Reload
// so the in-memory cert cache gets picked up immediately.
func ApiCertificateRegenerate(w http.ResponseWriter, r *http.Request, temp gatesentryWebserverTypes.TemporaryRuntime) {
	if temp.Reload == nil {
		http.Error(w, "runtime not wired", http.StatusInternalServerError)
		return
	}
	certPEM, _, err := temp.ReloadCACertificate()
	if err != nil {
		log.Printf("[Cert] Regenerate failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	temp.Reload()
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(certPEM))
}