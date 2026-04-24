package server_test

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/RootEvidence/honeypot/config"
	"github.com/RootEvidence/honeypot/server"
	"github.com/stretchr/testify/require"
)

// TestSSL_CertCNAndOrgMatch verifies that the TLS listener presents a certificate
// whose CN and Org match the ssl config values — satisfying the Nuclei template
// that checks subject_cn for "Fortinet"/"FortiGate"/"FortiOS".
func TestSSL_CertCNAndOrgMatch(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	cve := &config.CVE{
		ID:       "CVE-2024-23113",
		Protocol: "ssl",
		Port:     541,
		SSL: &config.SSLConfig{
			CertCN:  "FortiGate-VM64",
			CertOrg: "Fortinet",
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	mgr, err := server.NewSSLManager([]*config.CVE{cve}, zap.NewNop())
	require.NoError(t, err)

	go mgr.ServeListener(ctx, ln, cve) //nolint:errcheck

	// Connect with InsecureSkipVerify — we just want to inspect the cert.
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp",
		ln.Addr().String(),
		&tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	)
	require.NoError(t, err)
	defer conn.Close()

	require.NoError(t, conn.Handshake())
	certs := conn.ConnectionState().PeerCertificates
	require.NotEmpty(t, certs)

	leaf := certs[0]
	require.Equal(t, "FortiGate-VM64", leaf.Subject.CommonName)
	require.Contains(t, leaf.Subject.Organization, "Fortinet")
}

// TestSSL_ContextCancellationStopsAccept verifies graceful shutdown.
func TestSSL_ContextCancellationStopsAccept(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	cve := &config.CVE{
		ID:       "CVE-2024-23113",
		Protocol: "ssl",
		Port:     541,
		SSL:      &config.SSLConfig{CertCN: "FortiGate-VM64", CertOrg: "Fortinet"},
	}

	ctx, cancel := context.WithCancel(context.Background())

	mgr, err := server.NewSSLManager([]*config.CVE{cve}, zap.NewNop())
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		mgr.ServeListener(ctx, ln, cve) //nolint:errcheck
	}()

	cancel()
	select {
	case <-done:
		// goroutine exited cleanly
	case <-time.After(2 * time.Second):
		t.Fatal("ServeListener did not stop after context cancellation")
	}
}
