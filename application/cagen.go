package gatesentryf

// Gatesentry CA certificate generation.
//
// The HTTPS MITM flow needs a CA certificate to sign forged per-host
// certificates (see gatesentryproxy/ssl.go). On first run we generate a
// fresh RSA-4096 self-signed root CA valid for 100 years; the admin can
// regenerate it via /api/certificate/regenerate (e.g., to roll the key
// after a suspected compromise).
//
// The CA is stored in the buntdb-backed GSSettings store under the keys
// "capem" (PEM cert) and "keypem" (PEM private key), matching the
// fields the rest of the codebase already consumes via
// gatesentryproxy.InitWithDataCerts.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// caCommonName is the Subject CN of the Gatesentry root CA. Shown in
// the trust dialog when admins install the CA on their devices.
const caCommonName = "GateSentryFilter"

// caValidity is the lifetime of the generated CA certificate. 100 years
// is well beyond the practical lifespan of any installation and avoids
// the need for routine renewal.
const caValidity = 100 * 365 * 24 * time.Hour

// caKeyBits is the RSA key size for the CA. 4096-bit is overkill for a
// private proxy CA but matches what most enterprise CAs ship today.
const caKeyBits = 4096

// generateCA returns a freshly generated self-signed CA certificate
// (PEM-encoded) and its matching RSA private key (PEM-encoded).
func generateCA() (certPEM string, keyPEM string, err error) {
	privKey, err := rsa.GenerateKey(rand.Reader, caKeyBits)
	if err != nil {
		return "", "", fmt.Errorf("rsa.GenerateKey: %w", err)
	}

	// Use a random serial number so admins running multiple instances
	// don't end up with identical CA certs.
	serialMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialMax)
	if err != nil {
		return "", "", fmt.Errorf("rand.Int: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   caCommonName,
			Organization: []string{"GateSentry"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return "", "", fmt.Errorf("x509.CreateCertificate: %w", err)
	}

	certPEMBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	keyPEMBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	return string(certPEMBytes), string(keyPEMBytes), nil
}

// RegenerateCACertificate generates a fresh CA cert+key, stores them in
// the runtime settings store, and returns them so the caller can update
// in-process state and respond with the new PEM.
//
// Existing clients that trusted the old CA will need to install the new
// one. This is the documented trade-off for rolling the CA key.
func (R *GSRuntime) RegenerateCACertificate() (certPEM string, keyPEM string, err error) {
	certPEM, keyPEM, err = generateCA()
	if err != nil {
		return "", "", err
	}
	R.GSSettings.Update("capem", certPEM)
	R.GSSettings.Update("keypem", keyPEM)
	return certPEM, keyPEM, nil
}