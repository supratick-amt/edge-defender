// honeypot is a config-driven CVE simulator. It serves hardcoded vulnerable
// responses across HTTP, HTTPS, TCP, and TLS so Nuclei templates can be verified
// against it without touching real infrastructure.
//
// Env vars:
//
//	CONFIG_DIR         — directory of CVE YAML files (default: ./configs)
//	LOG_DIR            — write JSON logs here in addition to stdout (optional)
//	LOG_LEVEL          — zap log level: debug/info/warn/error (default: info)
//	HTTP_PORT          — HTTP fallback port when no CVE declares an http port (default: 80)
//	TCP_ENABLED        — start TCP listeners (default: true)
//	SSL_ENABLED        — start SSL/TLS listeners (default: true)
//	INTERACTSH_SERVER  — host:port of interactsh-server for OAST callbacks (optional)
package main

import (
	"context"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"go.uber.org/zap"

	"github.com/RootEvidence/honeypot/config"
	"github.com/RootEvidence/honeypot/logging"
	"github.com/RootEvidence/honeypot/server"
)

func main() {
	log, err := logging.New(envOr("LOG_LEVEL", "info"), envOr("LOG_DIR", ""))
	if err != nil {
		os.Stderr.WriteString("logger init: " + err.Error() + "\n")
		os.Exit(1)
	}
	defer log.Sync() //nolint:errcheck // best-effort flush on exit

	configDir := envOr("CONFIG_DIR", "./configs")
	cves, err := config.LoadDir(configDir)
	if err != nil {
		log.Warn("some CVE configs failed to load", zap.Error(err))
	}
	if len(cves) == 0 {
		log.Fatal("no CVE configs loaded", zap.String("config_dir", configDir))
	}

	log.Info("CVE configs loaded",
		zap.String("config_dir", configDir),
		zap.Int("count", len(cves)),
	)

	httpFallbackPort, err := strconv.Atoi(envOr("HTTP_PORT", "80"))
	if err != nil {
		log.Fatal("invalid HTTP_PORT", zap.Error(err))
	}

	interactshServer := envOr("INTERACTSH_SERVER", "")
	if interactshServer != "" {
		log.Info("OAST callbacks enabled", zap.String("interactsh_server", interactshServer))
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	log.Info("honeypot starting")

	// HTTP: one server per unique port declared in http CVEs.
	// CVEs without an explicit port contribute to the fallback port only.
	httpPorts := collectPorts(cves, "http")
	if len(httpPorts) == 0 {
		httpPorts = []int{httpFallbackPort}
	}
	// The fallback port gets all http CVEs (backward compat — existing CVEs without
	// explicit ports bind to the fallback). Additional ports get only their own CVEs.
	httpErrCh := make(chan error, len(httpPorts))
	for _, p := range httpPorts {
		var srvCVEs []*config.CVE
		if p == httpFallbackPort {
			srvCVEs = cves // all CVEs for the fallback port
		} else {
			srvCVEs = filterCVEsByPort(cves, "http", p)
		}
		srv := server.New(p, srvCVEs, log, interactshServer)
		go func(s *server.Server) { httpErrCh <- s.Start(ctx) }(srv)
	}

	// HTTPS: one server per unique port declared in https CVEs.
	httpsPorts := collectPorts(cves, "https")
	for _, p := range httpsPorts {
		httpsCVEs := filterCVEsByPort(cves, "https", p)
		srv, err := server.NewHTTPS(p, httpsCVEs, log, interactshServer)
		if err != nil {
			log.Error("HTTPS server init failed", zap.Int("port", p), zap.Error(err))
			continue
		}
		go func(s *server.Server) {
			if err := s.Start(ctx); err != nil {
				log.Error("HTTPS server error", zap.Error(err))
			}
		}(srv)
	}

	// TCP: best-effort — a port conflict logs an error but does not crash.
	if envBool("TCP_ENABLED", true) {
		tcpMgr := server.NewTCPManager(cves, log)
		go tcpMgr.Start(ctx) //nolint:errcheck
	}

	// SSL: cert generation can fail (bad config), so log but continue.
	if envBool("SSL_ENABLED", true) {
		sslMgr, err := server.NewSSLManager(cves, log)
		if err != nil {
			log.Error("SSL manager init failed", zap.Error(err))
		} else {
			go sslMgr.Start(ctx) //nolint:errcheck
		}
	}

	// Wait for the first HTTP server to exit — in practice this is the signal-driven
	// shutdown path. HTTPS servers are fire-and-forget (errors logged inline above).
	if err := <-httpErrCh; err != nil {
		log.Error("HTTP server error", zap.Error(err))
		os.Exit(1)
	}
	log.Info("honeypot stopped")
}

// collectPorts returns the unique set of ports declared by CVEs with the given protocol.
// CVEs without an explicit port (EffectivePorts returns empty) are excluded.
func collectPorts(cves []*config.CVE, protocol string) []int {
	seen := make(map[int]bool)
	var ports []int
	for _, cve := range cves {
		if cve.Protocol != protocol {
			continue
		}
		for _, p := range cve.EffectivePorts() {
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}
	return ports
}

// filterCVEsByPort returns CVEs with the given protocol whose EffectivePorts
// includes port. CVEs without an explicit port are excluded.
func filterCVEsByPort(cves []*config.CVE, protocol string, port int) []*config.CVE {
	var out []*config.CVE
	for _, cve := range cves {
		if cve.Protocol != protocol {
			continue
		}
		for _, p := range cve.EffectivePorts() {
			if p == port {
				out = append(out, cve)
				break
			}
		}
	}
	return out
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envBool returns the boolean value of an env var, or def if unset or unparseable.
func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}
