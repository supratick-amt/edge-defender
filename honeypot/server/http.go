// Package server implements the HTTP and HTTPS listeners for the honeypot.
// Routes are built from the loaded CVE configs and matched by path (prefix or exact),
// method, and optional Host header. Every request is logged (matched and unmatched)
// so callers can observe exactly what traffic scanners send.
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
	"io"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/RootEvidence/honeypot/config"
)

// route is a compiled route entry ready for matching.
type route struct {
	cveID        string
	method       string // upper-case; "ANY" matches all methods
	path         string // matched as prefix unless exact is true
	exact        bool   // true = exact path match; false = prefix match (default)
	host         string // if non-empty, only match requests with this Host (port stripped)
	oastCallback *config.OASTCallbackConfig
	resp         config.HTTPResponse
}

// Server is the HTTP (or HTTPS) honeypot listener. When tlsConfig is non-nil,
// Start() wraps the TCP listener in TLS before serving.
type Server struct {
	port       int
	routes     []route
	oastTarget string     // host:port for interactsh-server; empty = OAST disabled
	tlsConfig  *tls.Config // non-nil for HTTPS servers
	log        *zap.Logger
	srv        *http.Server
}

// New builds the HTTP server from the given CVE configs.
// Only configs with protocol "http" contribute routes.
// oastTarget is the host:port of the interactsh-server (e.g. "interactsh-server:80").
// Pass empty string to disable OAST callbacks even when routes declare oast_callback.
func New(port int, cves []*config.CVE, log *zap.Logger, oastTarget string) *Server {
	s := &Server{port: port, oastTarget: oastTarget, log: log}
	for _, cve := range cves {
		if cve.Protocol != "http" || cve.HTTP == nil {
			continue
		}
		for _, r := range cve.HTTP.Routes {
			s.routes = append(s.routes, compileRoute(cve.ID, r))
		}
	}
	sortRoutes(s.routes)
	return s
}

// NewHTTPS builds an HTTPS server from the given CVE configs.
// Only configs with protocol "https" and a non-nil HTTPS block contribute routes.
// A self-signed TLS certificate is generated from the first matching CVE's HTTPS
// config. If multiple HTTPS CVEs share the same port, only the first cert is used
// (routes from all CVEs are merged).
func NewHTTPS(port int, cves []*config.CVE, log *zap.Logger, oastTarget string) (*Server, error) {
	s := &Server{port: port, oastTarget: oastTarget, log: log}

	var tlsCfg *tls.Config
	for _, cve := range cves {
		if cve.Protocol != "https" || cve.HTTPS == nil {
			continue
		}
		// Build TLS config from the first CVE that provides cert settings.
		if tlsCfg == nil {
			var err error
			tlsCfg, err = buildHTTPSTLSConfig(cve.HTTPS)
			if err != nil {
				return nil, fmt.Errorf("generate TLS config for %s: %w", cve.ID, err)
			}
		}
		for _, r := range cve.HTTPS.Routes {
			s.routes = append(s.routes, compileRoute(cve.ID, r))
		}
	}
	sortRoutes(s.routes)
	s.tlsConfig = tlsCfg
	return s, nil
}

// compileRoute converts a config HTTPRoute into a compiled route for matching.
func compileRoute(cveID string, r config.HTTPRoute) route {
	return route{
		cveID:        cveID,
		method:       strings.ToUpper(r.Method),
		path:         r.Path,
		exact:        r.Match == "exact",
		host:         r.Host,
		oastCallback: r.OASTCallback,
		resp:         r.Response,
	}
}

// sortRoutes sorts routes so that longer paths match first. When paths have equal
// length, host-specific routes sort before host-wildcard routes so a vhost route
// doesn't fall through to the wildcard for the same path.
func sortRoutes(routes []route) {
	sort.Slice(routes, func(i, j int) bool {
		if len(routes[i].path) == len(routes[j].path) {
			// Host-specific before host-wildcard at the same path length.
			iHasHost := routes[i].host != ""
			jHasHost := routes[j].host != ""
			if iHasHost != jHasHost {
				return iHasHost
			}
		}
		return len(routes[i].path) > len(routes[j].path)
	})
}

// Start listens on the configured port and serves requests until ctx is cancelled.
// It returns only after the HTTP server has shut down.
func (s *Server) Start(ctx context.Context) error {
	addr := fmt.Sprintf(":%d", s.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	return s.StartOnListener(ctx, ln)
}

// StartOnListener serves requests on the provided listener until ctx is cancelled.
// Exported so tests can inject OS-assigned listeners without binding privileged ports.
// When tlsConfig is set, the listener is wrapped in TLS.
func (s *Server) StartOnListener(ctx context.Context, ln net.Listener) error {
	addr := ln.Addr().String()
	proto := "http"
	if s.tlsConfig != nil {
		ln = tls.NewListener(ln, s.tlsConfig)
		proto = "https"
	}

	s.srv = &http.Server{
		Addr:    addr,
		Handler: s,
		// Defence-in-depth timeouts; templates are fast so these are generous.
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	s.log.Info("listener started",
		zap.String("proto", proto),
		zap.String("addr", addr),
		zap.Int("routes", len(s.routes)),
	)

	errCh := make(chan error, 1)
	go func() {
		if err := s.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.srv.Shutdown(shutCtx); err != nil {
			s.log.Warn("HTTP shutdown error", zap.Error(err))
		}
		return <-errCh
	case err := <-errCh:
		return err
	}
}

// ServeHTTP is the main request dispatch. It finds the first matching route by
// path prefix + method + optional Host header and returns the configured response.
// Unmatched requests get 404. Both cases are logged.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	srcIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	matched := s.match(r.Method, r.URL.Path, r.Host)

	if matched == nil {
		s.log.Info("request unmatched",
			zap.String("event", "request"),
			zap.String("protocol", "http"),
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("host", r.Host),
			zap.String("src_ip", srcIP),
			zap.Int("dst_port", s.port),
			zap.Int("response_status", http.StatusNotFound),
			zap.Int64("duration_ms", time.Since(start).Milliseconds()),
		)
		http.NotFound(w, r)
		return
	}

	// Read body once so both OAST extraction and echo can use it.
	// Limit to 64 KB — templates never send more than a few KB.
	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, _ = io.ReadAll(io.LimitReader(r.Body, 64*1024))
	}

	// Trigger OAST callback if the route declares one and oastTarget is configured.
	if matched.oastCallback != nil {
		s.fireOASTCallback(matched.oastCallback, r, bodyBytes)
	}

	// Determine response body: echo extracts from request body, otherwise use static body.
	respBody := matched.resp.Body
	if matched.resp.Echo != nil {
		extracted, ok := extractGroup1(matched.resp.Echo.ExtractRegex, string(bodyBytes))
		if !ok {
			s.log.Warn("echo extraction failed",
				zap.String("cve", matched.cveID),
				zap.String("regex", matched.resp.Echo.ExtractRegex),
			)
			http.NotFound(w, r)
			return
		}
		respBody = extracted
	}

	// Write configured headers before the status code.
	for k, v := range matched.resp.Headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(matched.resp.Status)
	// HEAD responses must not include a body (RFC 9110 §9.3.2).
	if r.Method != http.MethodHead {
		fmt.Fprint(w, respBody)
	}

	s.log.Info("request matched",
		zap.String("event", "request"),
		zap.String("protocol", "http"),
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("host", r.Host),
		zap.String("src_ip", srcIP),
		zap.Int("dst_port", s.port),
		zap.String("cve_matched", matched.cveID),
		zap.String("matched_route", matched.method+" "+matched.path),
		zap.Int("response_status", matched.resp.Status),
		zap.Int64("duration_ms", time.Since(start).Milliseconds()),
	)
}

// match returns the first route whose path, method, and optional host all match.
// reqHost is the raw value of the Host header (may include a port suffix).
// The port suffix is stripped before comparing to the route's host field.
// Prefix routes match any path that starts with the configured path; exact routes
// require equality. Returns nil if no route matches.
func (s *Server) match(reqMethod, reqPath, reqHost string) *route {
	upper := strings.ToUpper(reqMethod)
	// Strip port from Host header before matching (e.g. "app1.local:8080" → "app1.local").
	host, _, err := net.SplitHostPort(reqHost)
	if err != nil {
		// No port suffix — use the value as-is.
		host = reqHost
	}
	for i := range s.routes {
		r := &s.routes[i]
		// Path check.
		if r.exact {
			if reqPath != r.path {
				continue
			}
		} else {
			if !strings.HasPrefix(reqPath, r.path) {
				continue
			}
		}
		// Host check: if the route has a host constraint, it must match.
		if r.host != "" && r.host != host {
			continue
		}
		if r.method == "ANY" || r.method == upper {
			return r
		}
	}
	return nil
}

// buildHTTPSTLSConfig generates a self-signed ECDSA certificate for the given HTTPS
// config and returns a *tls.Config that presents it. The cert includes DNS SANs so
// TLS clients can verify the hostname. When CertSANs is empty, sensible defaults
// are used: [certCN, "honeypot", "honeypot.local", "localhost"].
func buildHTTPSTLSConfig(cfg *config.HTTPSConfig) (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	sans := cfg.CertSANs
	if len(sans) == 0 {
		sans = []string{cfg.CertCN, "honeypot", "honeypot.local", "localhost"}
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cfg.CertCN,
			Organization: []string{cfg.CertOrg},
		},
		DNSNames:              sans,
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

// fireOASTCallback extracts an interactsh URL from the request and fires an
// async HTTP GET to oastTarget with the Host header set to the extracted
// hostname. Non-blocking: the caller's response is not affected by callback
// success or failure. If oastTarget is empty, the callback is skipped.
func (s *Server) fireOASTCallback(cfg *config.OASTCallbackConfig, r *http.Request, body []byte) {
	if s.oastTarget == "" {
		s.log.Debug("OAST callback skipped: no oast target configured")
		return
	}

	var src string
	switch cfg.ExtractFrom {
	case "header":
		src = r.Header.Get(cfg.HeaderName)
	case "body":
		src = string(body)
	default:
		s.log.Debug("OAST callback skipped: unknown extract_from", zap.String("extract_from", cfg.ExtractFrom))
		return
	}

	interactURL, ok := extractGroup1(cfg.ExtractRegex, src)
	if !ok {
		s.log.Debug("OAST callback skipped: regex did not match", zap.String("regex", cfg.ExtractRegex))
		return
	}

	// Parse the hostname from the extracted interactsh URL so we can set the
	// Host header on the outbound request. The oastTarget is the reachable
	// address (host:port); the extracted hostname is the OAST identifier.
	parsed, err := parseHost(interactURL)
	if err != nil {
		s.log.Debug("OAST callback skipped: could not parse host from URL",
			zap.String("url", interactURL), zap.Error(err))
		return
	}

	oastTarget := s.oastTarget
	log := s.log
	go func() {
		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequest(http.MethodGet, "http://"+oastTarget+"/", nil)
		if err != nil {
			log.Debug("OAST callback request build failed", zap.Error(err))
			return
		}
		req.Host = parsed
		log.Debug("firing OAST callback", zap.String("host", parsed), zap.String("target", oastTarget))
		resp, err := client.Do(req)
		if err != nil {
			log.Debug("OAST callback failed", zap.String("host", parsed), zap.Error(err))
			return
		}
		resp.Body.Close()
		log.Debug("OAST callback succeeded", zap.String("host", parsed), zap.Int("status", resp.StatusCode))
	}()
}

// parseHost returns the hostname from a URL string, stripping the scheme and
// any path or query. Interactsh URLs look like http://abc123.honeypot.local —
// no port — so we just need to strip the scheme and any trailing path.
func parseHost(rawURL string) (string, error) {
	host := strings.TrimPrefix(rawURL, "https://")
	host = strings.TrimPrefix(host, "http://")
	if idx := strings.IndexByte(host, '/'); idx >= 0 {
		host = host[:idx]
	}
	if host == "" {
		return "", fmt.Errorf("empty host in %q", rawURL)
	}
	return host, nil
}

// extractGroup1 compiles re and returns capture group 1 from s.
// Returns ("", false) when the regex does not match or has no groups.
func extractGroup1(re, s string) (string, bool) {
	compiled, err := regexp.Compile(re)
	if err != nil {
		return "", false
	}
	m := compiled.FindStringSubmatch(s)
	if len(m) < 2 {
		return "", false
	}
	return m[1], true
}
