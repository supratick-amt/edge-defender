// Package server — ssl.go implements the TLS listener for SSL-protocol CVEs.
// A self-signed cert is generated at startup from the ssl config (cert_cn, cert_org).
// The listener completes the TLS handshake so Nuclei can inspect certificate metadata,
// then closes the connection. No application data is exchanged.
package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"go.uber.org/zap"

	"github.com/RootEvidence/honeypot/config"
)

// SSLManager starts and manages TLS listeners for all SSL-protocol CVEs.
type SSLManager struct {
	// certs maps CVE ID to the TLS config with the generated certificate.
	certs map[string]*tls.Config
	cves  []*config.CVE
	log   *zap.Logger
}

// NewSSLManager creates an SSLManager and generates self-signed certificates for
// each CVE with protocol "ssl". Generation errors are returned immediately rather
// than deferred to Start, so bad configs fail fast at startup.
func NewSSLManager(cves []*config.CVE, log *zap.Logger) (*SSLManager, error) {
	m := &SSLManager{
		certs: make(map[string]*tls.Config),
		log:   log,
	}
	for _, c := range cves {
		if c.Protocol != "ssl" || c.SSL == nil {
			continue
		}
		tlsCfg, err := buildTLSConfig(c.SSL)
		if err != nil {
			return nil, fmt.Errorf("generate cert for %s: %w", c.ID, err)
		}
		m.certs[c.ID] = tlsCfg
		m.cves = append(m.cves, c)
	}
	return m, nil
}

// Start binds a listener on each port for each SSL CVE and serves until ctx is cancelled.
// Bind errors are logged and skipped.
func (m *SSLManager) Start(ctx context.Context) error {
	for _, cve := range m.cves {
		for _, port := range cve.EffectivePorts() {
			ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
			if err != nil {
				m.log.Error("SSL bind failed",
					zap.String("cve", cve.ID),
					zap.Int("port", port),
					zap.Error(err),
				)
				continue
			}
			m.log.Info("SSL listener started",
				zap.String("cve", cve.ID),
				zap.Int("port", port),
			)
			go m.ServeListener(ctx, ln, cve) //nolint:errcheck
		}
	}
	<-ctx.Done()
	return nil
}

// ServeListener accepts TLS connections on ln until ctx is cancelled.
// Exported so tests can inject pre-bound listeners on OS-assigned ports.
func (m *SSLManager) ServeListener(ctx context.Context, ln net.Listener, cve *config.CVE) error {
	tlsCfg, ok := m.certs[cve.ID]
	if !ok {
		// Should not happen if NewSSLManager was used — defensive only.
		m.log.Error("no TLS config for CVE", zap.String("cve", cve.ID))
		return fmt.Errorf("no TLS config for %s", cve.ID)
	}

	// Wrap plain listener in TLS.
	tlsLn := tls.NewListener(ln, tlsCfg)

	go func() {
		<-ctx.Done()
		tlsLn.Close()
	}()

	for {
		conn, err := tlsLn.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				m.log.Error("SSL accept error",
					zap.String("cve", cve.ID),
					zap.Error(err),
				)
				return err
			}
		}
		go m.handleConn(conn, cve)
	}
}

func (m *SSLManager) handleConn(conn net.Conn, cve *config.CVE) {
	defer conn.Close()
	start := time.Now()

	srcIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	dstPort := portFromAddr(conn.LocalAddr().String())

	// Complete the TLS handshake — this is what Nuclei triggers to read the cert.
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	tlsConn.SetDeadline(time.Now().Add(tcpReadWriteTimeout)) //nolint:errcheck
	if err := tlsConn.Handshake(); err != nil {
		// Clients that close before completing the handshake are expected (e.g. port scanners).
		m.log.Debug("SSL handshake error",
			zap.String("cve", cve.ID),
			zap.String("src_ip", srcIP),
			zap.Error(err),
		)
		return
	}

	m.log.Info("connection",
		zap.String("event", "connection"),
		zap.String("protocol", "ssl"),
		zap.String("src_ip", srcIP),
		zap.Int("dst_port", dstPort),
		zap.String("cve_matched", cve.ID),
		zap.Int("bytes_read", 0),
		zap.Int("bytes_written", 0),
		zap.Int64("duration_ms", time.Since(start).Milliseconds()),
	)
}

// buildTLSConfig generates a self-signed ECDSA certificate for the given SSL config
// and returns a *tls.Config that presents it. The cert is valid for 1 year.
func buildTLSConfig(cfg *config.SSLConfig) (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cfg.CertCN,
			Organization: []string{cfg.CertOrg},
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("build key pair: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}
