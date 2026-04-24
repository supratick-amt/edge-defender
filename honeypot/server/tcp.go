// Package server — tcp.go implements the TCP banner/read-first responder.
// Each CVE with protocol "tcp" gets one goroutine per declared port, managed by TCPManager.
package server

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"go.uber.org/zap"

	"github.com/RootEvidence/honeypot/config"
)

// delayOrCancel sleeps for d, returning early if ctx is cancelled.
// Returns true if the delay completed, false if ctx was cancelled first.
func delayOrCancel(ctx context.Context, d time.Duration) bool {
	select {
	case <-time.After(d):
		return true
	case <-ctx.Done():
		return false
	}
}

const (
	tcpReadWriteTimeout = 10 * time.Second
)

// TCPManager starts and manages TCP listeners for all TCP-protocol CVEs.
type TCPManager struct {
	cves []*config.CVE
	log  *zap.Logger
}

// NewTCPManager creates a manager for the subset of cves with protocol "tcp".
func NewTCPManager(cves []*config.CVE, log *zap.Logger) *TCPManager {
	var tcp []*config.CVE
	for _, c := range cves {
		if c.Protocol == "tcp" && c.TCP != nil {
			tcp = append(tcp, c)
		}
	}
	return &TCPManager{cves: tcp, log: log}
}

// Start binds a listener on each port for each TCP CVE and serves until ctx is cancelled.
// Bind errors are logged and skipped — a port already in use does not abort other listeners.
func (m *TCPManager) Start(ctx context.Context) error {
	for _, cve := range m.cves {
		for _, port := range cve.EffectivePorts() {
			ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
			if err != nil {
				m.log.Error("TCP bind failed",
					zap.String("cve", cve.ID),
					zap.Int("port", port),
					zap.Error(err),
				)
				continue
			}
			m.log.Info("TCP listener started",
				zap.String("cve", cve.ID),
				zap.Int("port", port),
			)
			go m.ServeListener(ctx, ln, cve) //nolint:errcheck
		}
	}
	// Block until context is cancelled so callers can wait on this.
	<-ctx.Done()
	return nil
}

// ServeListener accepts connections on ln until ctx is cancelled, then closes ln.
// It is exported so tests can inject pre-bound listeners on OS-assigned ports.
func (m *TCPManager) ServeListener(ctx context.Context, ln net.Listener, cve *config.CVE) error {
	// Close the listener when ctx fires so the blocking Accept() unblocks.
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			// Distinguish context-driven closure from real errors.
			select {
			case <-ctx.Done():
				return nil
			default:
				m.log.Error("TCP accept error",
					zap.String("cve", cve.ID),
					zap.Error(err),
				)
				return err
			}
		}
		go m.handleConn(ctx, conn, cve)
	}
}

func (m *TCPManager) handleConn(ctx context.Context, conn net.Conn, cve *config.CVE) {
	defer conn.Close()
	start := time.Now()

	srcIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	dstPort := portFromAddr(conn.LocalAddr().String())

	delay := time.Duration(cve.TCP.ResponseDelayMs) * time.Millisecond

	// tcpwrapped: complete the handshake then close with no data exchange.
	// Nmap identifies such ports as service "tcpwrapped".
	// We apply the delay before closing so the port can appear slow-to-drop,
	// which is consistent with the delay semantics for banner/read-first modes.
	if cve.TCP.TCPWrapped {
		if delay > 0 {
			if !delayOrCancel(ctx, delay) {
				return
			}
		}
		m.log.Info("connection",
			zap.String("event", "connection"),
			zap.String("protocol", "tcp"),
			zap.String("src_ip", srcIP),
			zap.Int("dst_port", dstPort),
			zap.String("cve_matched", cve.ID),
			zap.Int("bytes_read", 0),
			zap.Int("bytes_written", 0),
			zap.Int64("duration_ms", time.Since(start).Milliseconds()),
		)
		return
	}

	// Extend the I/O deadline to cover the configured delay so the write
	// after a long sleep doesn't fail on an already-elapsed deadline.
	conn.SetDeadline(time.Now().Add(tcpReadWriteTimeout + delay)) //nolint:errcheck

	var bytesRead int

	if cve.TCP.ReadFirst {
		size := cve.TCP.ReadSize
		if size <= 0 {
			size = 1024
		}
		buf := make([]byte, size)
		n, err := conn.Read(buf)
		if err != nil {
			m.log.Warn("TCP read error",
				zap.String("cve", cve.ID),
				zap.String("src_ip", srcIP),
				zap.Error(err),
			)
			return
		}
		bytesRead = n
	}

	if delay > 0 {
		if !delayOrCancel(ctx, delay) {
			return
		}
	}

	payload, err := m.payload(cve.TCP)
	if err != nil {
		m.log.Error("TCP payload error",
			zap.String("cve", cve.ID),
			zap.Error(err),
		)
		return
	}

	n, _ := conn.Write(payload)

	m.log.Info("connection",
		zap.String("event", "connection"),
		zap.String("protocol", "tcp"),
		zap.String("src_ip", srcIP),
		zap.Int("dst_port", dstPort),
		zap.String("cve_matched", cve.ID),
		zap.Int("bytes_read", bytesRead),
		zap.Int("bytes_written", n),
		zap.Int64("duration_ms", time.Since(start).Milliseconds()),
	)
}

// payload returns the bytes to send for the connection. ResponseHex takes
// precedence over Banner; if neither is set, an empty slice is returned.
func (m *TCPManager) payload(cfg *config.TCPConfig) ([]byte, error) {
	if cfg.ResponseHex != "" {
		b, err := hex.DecodeString(cfg.ResponseHex)
		if err != nil {
			return nil, fmt.Errorf("decode response_hex: %w", err)
		}
		return b, nil
	}
	return []byte(cfg.Banner), nil
}

// portFromAddr extracts the port as an int from a "host:port" string.
// Returns 0 on parse error (non-fatal; only affects logging).
func portFromAddr(addr string) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return port
}
