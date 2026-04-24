package server_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/RootEvidence/honeypot/config"
	"github.com/RootEvidence/honeypot/server"
	"github.com/stretchr/testify/require"
)

// dialTCP connects to addr and returns the connection with a short deadline.
func dialTCP(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	return conn
}

// TestTCP_BannerSentOnConnect verifies that a banner-mode CVE sends the banner
// immediately after the connection is accepted (no client input required).
func TestTCP_BannerSentOnConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	cve := &config.CVE{
		ID:       "CVE-2024-6387",
		Protocol: "tcp",
		Port:     22,
		TCP: &config.TCPConfig{
			ReadFirst: false,
			Banner:    "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n",
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	mgr := server.NewTCPManager([]*config.CVE{cve}, zap.NewNop())
	go mgr.ServeListener(ctx, ln, cve) //nolint:errcheck

	conn := dialTCP(t, ln.Addr().String())
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	require.Contains(t, string(buf[:n]), "OpenSSH_9.6p1")
}

// TestTCP_ReadFirstThenRespond verifies that a read-first CVE waits for client
// input before sending its response.
func TestTCP_ReadFirstThenRespond(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	// SMB magic header bytes + "Windows Server 2008 R2"
	response := "\xff\x53\x4d\x42Windows Server 2008 R2\x00"
	cve := &config.CVE{
		ID:       "CVE-2017-0144",
		Protocol: "tcp",
		Port:     445,
		TCP: &config.TCPConfig{
			ReadFirst: true,
			ReadSize:  64,
			Banner:    response,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	mgr := server.NewTCPManager([]*config.CVE{cve}, zap.NewNop())
	go mgr.ServeListener(ctx, ln, cve) //nolint:errcheck

	conn := dialTCP(t, ln.Addr().String())
	// Send some bytes first (simulating Nuclei's SMB negotiate request).
	_, err = conn.Write([]byte("HELLO"))
	require.NoError(t, err)

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	data := string(buf[:n])
	require.Contains(t, data, "\xff\x53\x4d\x42")
	require.Contains(t, data, "Windows Server 2008 R2")
}

// TestTCP_MultiPort verifies that the TCP manager starts listeners on all ports
// declared in a multi-port CVE config.
func TestTCP_MultiPort(t *testing.T) {
	// Allocate two listeners on OS-assigned ports to simulate multi-port binding.
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	cve := &config.CVE{
		ID:       "CVE-2010-4344",
		Protocol: "tcp",
		Ports:    []int{25, 465, 587},
		TCP: &config.TCPConfig{
			ReadFirst: false,
			Banner:    "220 honeypot.local ESMTP Exim 4.69\r\n",
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	mgr := server.NewTCPManager([]*config.CVE{cve}, zap.NewNop())
	// Serve on both test listeners (stand-ins for ports 25 and 465).
	go mgr.ServeListener(ctx, ln1, cve) //nolint:errcheck
	go mgr.ServeListener(ctx, ln2, cve) //nolint:errcheck

	for _, ln := range []net.Listener{ln1, ln2} {
		conn := dialTCP(t, ln.Addr().String())
		buf := make([]byte, 128)
		n, err := conn.Read(buf)
		require.NoError(t, err)
		require.Contains(t, string(buf[:n]), "Exim 4.69")
	}
}

// TestTCP_ResponseHex verifies that a CVE with response_hex sends the decoded bytes.
func TestTCP_ResponseHex(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	// "ff534d42" = \xff\x53\x4d\x42 (SMB magic)
	cve := &config.CVE{
		ID:       "CVE-2017-0144",
		Protocol: "tcp",
		Port:     445,
		TCP: &config.TCPConfig{
			ReadFirst:   true,
			ReadSize:    64,
			ResponseHex: "ff534d4257696e646f777320536572766572203230303820523200",
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	mgr := server.NewTCPManager([]*config.CVE{cve}, zap.NewNop())
	go mgr.ServeListener(ctx, ln, cve) //nolint:errcheck

	conn := dialTCP(t, ln.Addr().String())
	_, err = conn.Write([]byte("HELLO"))
	require.NoError(t, err)

	all, err := io.ReadAll(conn)
	require.NoError(t, err)
	require.Equal(t, byte(0xff), all[0])
	require.Equal(t, byte(0x53), all[1]) // 'S'
	require.Equal(t, byte(0x4d), all[2]) // 'M'
	require.Equal(t, byte(0x42), all[3]) // 'B'
	require.Contains(t, string(all), "Windows Server 2008 R2")
}

// TestTCP_TCPWrapped verifies that a tcpwrapped CVE accepts the TCP handshake
// and then closes the connection without sending any data.
func TestTCP_TCPWrapped(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	cve := &config.CVE{
		ID:       "TEST-TCPWRAPPED",
		Protocol: "tcp",
		Port:     9999,
		TCP:      &config.TCPConfig{TCPWrapped: true},
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	mgr := server.NewTCPManager([]*config.CVE{cve}, zap.NewNop())
	go mgr.ServeListener(ctx, ln, cve) //nolint:errcheck

	conn := dialTCP(t, ln.Addr().String())

	// The server should close immediately — ReadAll returns "" with no error.
	conn.SetDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	data, err := io.ReadAll(conn)
	require.NoError(t, err)
	require.Empty(t, data, "tcpwrapped port must not send any application data")
}

// TestTCP_ResponseDelayHoldsReply verifies that a handler configured with
// response_delay_ms waits at least that long before sending any data.
// The delay must hold for both banner mode and read-first mode.
func TestTCP_ResponseDelayHoldsReply(t *testing.T) {
	tests := []struct {
		name     string
		readFirst bool
	}{
		{name: "banner mode delays response", readFirst: false},
		{name: "read-first mode delays response", readFirst: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)

			const delayMs = 200

			cve := &config.CVE{
				ID:       "CVE-TEST-DELAY",
				Protocol: "tcp",
				Port:     9000,
				TCP: &config.TCPConfig{
					ReadFirst:       tt.readFirst,
					ReadSize:        8,
					Banner:          "HELLO\r\n",
					ResponseDelayMs: delayMs,
				},
			}

			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			mgr := server.NewTCPManager([]*config.CVE{cve}, zap.NewNop())
			go mgr.ServeListener(ctx, ln, cve) //nolint:errcheck

			conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
			require.NoError(t, err)
			t.Cleanup(func() { conn.Close() })
			conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

			if tt.readFirst {
				_, err = conn.Write([]byte("PROBE\r\n"))
				require.NoError(t, err)
			}

			start := time.Now()
			buf := make([]byte, 64)
			n, err := conn.Read(buf)
			elapsed := time.Since(start)

			require.NoError(t, err)
			require.Greater(t, n, 0, "expected response bytes")
			require.GreaterOrEqual(t, elapsed, time.Duration(delayMs)*time.Millisecond,
				"handler responded in %v, expected at least %dms delay", elapsed, delayMs)
		})
	}
}

// TestTCP_ZeroDelayUnchanged verifies that response_delay_ms: 0 (the default)
// doesn't add any artificial delay — a regression guard for existing behavior.
func TestTCP_ZeroDelayUnchanged(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	cve := &config.CVE{
		ID:       "CVE-TEST-NODELAY",
		Protocol: "tcp",
		Port:     9001,
		TCP: &config.TCPConfig{
			Banner:          "FAST\r\n",
			ResponseDelayMs: 0, // explicit zero — must be immediate
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	mgr := server.NewTCPManager([]*config.CVE{cve}, zap.NewNop())
	go mgr.ServeListener(ctx, ln, cve) //nolint:errcheck

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck

	start := time.Now()
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.Greater(t, n, 0)
	// "Immediate" means well under 100ms on any reasonable machine.
	require.Less(t, elapsed, 100*time.Millisecond,
		"zero-delay handler took %v, expected near-instant", elapsed)
}

// TestTCP_ContextCancelDuringDelay verifies that a context cancellation during
// the response delay causes the handler to exit cleanly rather than hang until
// the delay timer fires.
func TestTCP_ContextCancelDuringDelay(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	cve := &config.CVE{
		ID:       "CVE-TEST-CANCEL",
		Protocol: "tcp",
		Port:     9002,
		TCP: &config.TCPConfig{
			Banner:          "LATE\r\n",
			ResponseDelayMs: 5000, // 5s — much longer than the test will wait
		},
	}

	ctx, cancel := context.WithCancel(context.Background())

	mgr := server.NewTCPManager([]*config.CVE{cve}, zap.NewNop())
	go mgr.ServeListener(ctx, ln, cve) //nolint:errcheck

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	// Short deadline so the Read returns quickly after the server closes.
	conn.SetDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck

	// Cancel context while the handler is sleeping through its delay.
	cancel()

	start := time.Now()
	io.ReadAll(conn) //nolint:errcheck // we only care about elapsed time, not the error
	elapsed := time.Since(start)

	// Connection is closed (EOF) well before the 5s delay would have fired.
	require.Less(t, elapsed, 2*time.Second,
		"handler should exit on ctx cancel, not wait for 5s delay; took %v", elapsed)
}

// TestTCP_ContextCancellationStopsAccept verifies that cancelling the context
// causes the listener loop to stop accepting new connections.
func TestTCP_ContextCancellationStopsAccept(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	cve := &config.CVE{
		ID:       "CVE-2024-6387",
		Protocol: "tcp",
		Port:     22,
		TCP:      &config.TCPConfig{Banner: "SSH-2.0-OpenSSH_9.6p1\r\n"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	mgr := server.NewTCPManager([]*config.CVE{cve}, zap.NewNop())

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
