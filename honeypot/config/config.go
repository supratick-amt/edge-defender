// Package config loads and validates CVE YAML config files.
// Each file describes one CVE: which protocol it uses, which ports, and
// what routes/banners to serve. Protocol determines which listener handles it:
// "http" → HTTP listener, "tcp" → TCP listener, "ssl" → TLS listener.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// CVE is a single CVE config file. The Protocol field determines which listener
// handles it.
//
// Port and Ports are both supported for declaring listen ports. Ports takes
// precedence when set; Port is the backward-compatible single-port form.
// Use EffectivePorts() to get the canonical port list in all cases.
type CVE struct {
	ID       string `yaml:"id"`
	Name     string `yaml:"name"`
	Protocol string `yaml:"protocol"` // http | https | tcp | ssl
	Port     int    `yaml:"port,omitempty"`
	Ports    []int  `yaml:"ports,omitempty"`

	HTTP  *HTTPConfig  `yaml:"http,omitempty"`
	HTTPS *HTTPSConfig `yaml:"https,omitempty"`
	TCP   *TCPConfig   `yaml:"tcp,omitempty"`
	SSL   *SSLConfig   `yaml:"ssl,omitempty"`
}

// EffectivePorts returns the list of ports this CVE should listen on.
// Ports takes precedence over Port; if neither is set, the slice is empty.
func (c *CVE) EffectivePorts() []int {
	if len(c.Ports) > 0 {
		return c.Ports
	}
	if c.Port != 0 {
		return []int{c.Port}
	}
	return nil
}

// HTTPConfig holds the route table for an HTTP CVE.
type HTTPConfig struct {
	Routes []HTTPRoute `yaml:"routes"`
}

// OASTCallbackConfig describes how to extract an interactsh URL from the
// request and fire an outbound HTTP GET to trigger an OAST callback.
// extract_from must be "header" or "body"; extract_regex capture group 1 must
// yield the full URL (e.g. http://abc123.honeypot.local).
type OASTCallbackConfig struct {
	ExtractFrom  string `yaml:"extract_from"`  // "header" or "body"
	HeaderName   string `yaml:"header_name"`   // used when extract_from: header
	ExtractRegex string `yaml:"extract_regex"` // capture group 1 = the URL
}

// EchoConfig tells the server to extract a string from the request body and
// return it as the response body. This satisfies templates that send a random
// token and match body == token (e.g. CVE-2017-10271 randstr matching).
type EchoConfig struct {
	ExtractRegex string `yaml:"extract_regex"` // capture group 1 = response body
}

// HTTPRoute is one entry in the HTTP route table. Method can be HEAD, GET,
// POST, or ANY (matches any method). Match controls how Path is compared:
// "prefix" (default) matches any request path that starts with Path;
// "exact" requires the request path to equal Path (trailing slash is tolerated).
// Host, if non-empty, restricts the route to requests whose Host header matches
// exactly (port stripped). Host-specific routes take priority over host-wildcard
// routes at the same path length.
type HTTPRoute struct {
	Method       string              `yaml:"method"`
	Path         string              `yaml:"path"`
	Match        string              `yaml:"match,omitempty"`        // "prefix" (default) or "exact"
	Host         string              `yaml:"host,omitempty"`         // restrict to this Host header value
	OASTCallback *OASTCallbackConfig `yaml:"oast_callback,omitempty"`
	Response     HTTPResponse        `yaml:"response"`
}

// HTTPSConfig holds the TLS certificate settings and route table for an HTTPS
// CVE. The cert fields map directly to the self-signed certificate generated at
// startup. Routes use the same HTTPRoute type as HTTP.
type HTTPSConfig struct {
	CertCN   string      `yaml:"cert_cn"`
	CertOrg  string      `yaml:"cert_org"`
	CertSANs []string    `yaml:"cert_sans,omitempty"`
	Routes   []HTTPRoute `yaml:"routes"`
}

// HTTPResponse is the canned response returned when this route matches.
type HTTPResponse struct {
	Status  int               `yaml:"status"`
	Headers map[string]string `yaml:"headers,omitempty"`
	Body    string            `yaml:"body"`
	Echo    *EchoConfig       `yaml:"echo,omitempty"`
}

// TCPConfig describes a TCP banner responder.
//
// When TCPWrapped is true, the server completes the TCP handshake then closes
// immediately without reading or writing any data. Nmap reports such ports as
// "tcpwrapped". All other fields are ignored when TCPWrapped is true.
//
// ResponseDelayMs, when > 0, causes the handler to sleep for that many
// milliseconds before writing any response (banner or hex payload). This lets
// a port appear slow or stalled, which is useful for testing scanner probe
// timeouts. The sleep honours context cancellation so shutdown is not delayed.
type TCPConfig struct {
	TCPWrapped      bool   `yaml:"tcpwrapped"`
	ReadFirst       bool   `yaml:"read_first"`
	ReadSize        int    `yaml:"read_size,omitempty"`
	Banner          string `yaml:"banner,omitempty"`
	ResponseHex     string `yaml:"response_hex,omitempty"`
	ResponseDelayMs int    `yaml:"response_delay_ms,omitempty"`
}

// SSLConfig describes a TLS listener with a self-signed cert. Parsed but not yet used.
type SSLConfig struct {
	CertCN  string `yaml:"cert_cn"`
	CertOrg string `yaml:"cert_org"`
}

// LoadDir reads every *.yaml file in dir and returns the parsed CVE configs.
// Files that fail to parse are returned as an error; the valid ones are still returned.
func LoadDir(dir string) ([]*CVE, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read config dir %s: %w", dir, err)
	}

	var cves []*CVE
	var errs []string

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		cve, err := loadFile(path)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", entry.Name(), err))
			continue
		}
		cves = append(cves, cve)
	}

	if len(errs) > 0 {
		return cves, fmt.Errorf("config load errors: %s", strings.Join(errs, "; "))
	}
	return cves, nil
}

func loadFile(path string) (*CVE, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	var cve CVE
	if err := yaml.Unmarshal(data, &cve); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}

	if cve.ID == "" {
		return nil, fmt.Errorf("missing id field")
	}
	if cve.Protocol == "" {
		return nil, fmt.Errorf("missing protocol field")
	}

	return &cve, nil
}
