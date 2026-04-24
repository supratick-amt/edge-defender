package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/RootEvidence/honeypot/config"
	"github.com/stretchr/testify/require"
)

func TestLoadDir_ParsesHTTPRoutes(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "CVE-2010-0738.yaml", `
id: CVE-2010-0738
name: JBoss Test
protocol: http
port: 80
http:
  routes:
    - method: HEAD
      path: /jmx-console/
      response:
        status: 200
        headers:
          Content-Type: text/html
          Server: Apache-Coyote/1.1 JBoss/5.0
        body: ""
`)

	cves, err := config.LoadDir(dir)
	require.NoError(t, err)
	require.Len(t, cves, 1)

	cve := cves[0]
	require.Equal(t, "CVE-2010-0738", cve.ID)
	require.Equal(t, "http", cve.Protocol)
	require.Equal(t, 80, cve.Port)
	require.NotNil(t, cve.HTTP)
	require.Len(t, cve.HTTP.Routes, 1)

	r := cve.HTTP.Routes[0]
	require.Equal(t, "HEAD", r.Method)
	require.Equal(t, "/jmx-console/", r.Path)
	require.Equal(t, 200, r.Response.Status)
	require.Equal(t, "text/html", r.Response.Headers["Content-Type"])
}

func TestLoadDir_SkipsNonYAMLFiles(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "README.md", "not a config")
	write(t, dir, "CVE-2012-1823.yaml", `
id: CVE-2012-1823
name: PHP CGI
protocol: http
port: 80
http:
  routes: []
`)

	cves, err := config.LoadDir(dir)
	require.NoError(t, err)
	require.Len(t, cves, 1)
	require.Equal(t, "CVE-2012-1823", cves[0].ID)
}

func TestLoadDir_ReturnsPartialResultsOnBadFile(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "bad.yaml", "not: valid: yaml: at: all: {")
	write(t, dir, "CVE-2009-1151.yaml", `
id: CVE-2009-1151
name: phpMyAdmin
protocol: http
port: 80
http:
  routes: []
`)

	cves, err := config.LoadDir(dir)
	// One file failed so err is non-nil, but the valid file is still returned.
	require.Error(t, err)
	require.Len(t, cves, 1)
	require.Equal(t, "CVE-2009-1151", cves[0].ID)
}

func TestLoadDir_RejectsMissingID(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "no-id.yaml", `
name: No ID
protocol: http
port: 80
`)

	_, err := config.LoadDir(dir)
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing id")
}

func TestLoadDir_ParsesTCPAndSSLFieldsWithoutError(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "CVE-2024-6387.yaml", `
id: CVE-2024-6387
name: OpenSSH RegreSSHion
protocol: tcp
port: 22
tcp:
  read_first: false
  banner: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"
`)
	write(t, dir, "CVE-2024-23113.yaml", `
id: CVE-2024-23113
name: Fortinet FGFM
protocol: ssl
port: 541
ssl:
  cert_cn: FortiGate-VM64
  cert_org: Fortinet
`)

	cves, err := config.LoadDir(dir)
	require.NoError(t, err)
	require.Len(t, cves, 2)
}

func TestCVE_EffectivePorts_SinglePort(t *testing.T) {
	cve := &config.CVE{Port: 22}
	require.Equal(t, []int{22}, cve.EffectivePorts())
}

func TestCVE_EffectivePorts_MultiPort_PrefersPorts(t *testing.T) {
	// Ports takes precedence when both are set.
	cve := &config.CVE{Port: 25, Ports: []int{25, 465, 587}}
	require.Equal(t, []int{25, 465, 587}, cve.EffectivePorts())
}

func TestCVE_EffectivePorts_NeitherSet(t *testing.T) {
	cve := &config.CVE{}
	require.Empty(t, cve.EffectivePorts())
}

func TestLoadDir_ParsesMultiPortConfig(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "CVE-2010-4344.yaml", `
id: CVE-2010-4344
name: Exim SMTP Heap Overflow
protocol: tcp
ports: [25, 465, 587]
tcp:
  read_first: false
  banner: "220 honeypot.local ESMTP Exim 4.69\r\n"
`)

	cves, err := config.LoadDir(dir)
	require.NoError(t, err)
	require.Len(t, cves, 1)
	require.Equal(t, []int{25, 465, 587}, cves[0].EffectivePorts())
}

// TestOASTCallbackConfig_ParsedCorrectly verifies that oast_callback fields
// survive the YAML round-trip intact.
func TestOASTCallbackConfig_ParsedCorrectly(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "CVE-2015-2051.yaml", `
id: CVE-2015-2051
name: D-Link HNAP
protocol: http
port: 80
http:
  routes:
    - method: POST
      path: /HNAP1/
      oast_callback:
        extract_from: header
        header_name: SOAPAction
        extract_regex: 'wget\s+(https?://\S+)'
      response:
        status: 200
        body: ok
`)

	cves, err := config.LoadDir(dir)
	require.NoError(t, err)
	require.Len(t, cves, 1)

	r := cves[0].HTTP.Routes[0]
	require.NotNil(t, r.OASTCallback)
	require.Equal(t, "header", r.OASTCallback.ExtractFrom)
	require.Equal(t, "SOAPAction", r.OASTCallback.HeaderName)
	require.Equal(t, `wget\s+(https?://\S+)`, r.OASTCallback.ExtractRegex)
}

// TestEchoConfig_ParsedCorrectly verifies that echo fields survive the YAML
// round-trip intact.
func TestEchoConfig_ParsedCorrectly(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "CVE-2017-10271.yaml", `
id: CVE-2017-10271
name: WebLogic RCE
protocol: http
port: 80
http:
  routes:
    - method: POST
      path: /wls-wsat/CoordinatorPortType
      response:
        status: 200
        echo:
          extract_regex: '<string>([^<]+)</string>'
`)

	cves, err := config.LoadDir(dir)
	require.NoError(t, err)
	require.Len(t, cves, 1)

	r := cves[0].HTTP.Routes[0]
	require.Nil(t, r.OASTCallback)
	require.NotNil(t, r.Response.Echo)
	require.Equal(t, `<string>([^<]+)</string>`, r.Response.Echo.ExtractRegex)
}

// TestLoadDir_ParsesHTTPSConfig verifies that protocol: https with cert fields
// and routes survives the YAML round-trip.
func TestLoadDir_ParsesHTTPSConfig(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "TEST-HTTPS.yaml", `
id: TEST-HTTPS
name: HTTPS test
protocol: https
port: 443
https:
  cert_cn: honeypot.local
  cert_org: Honeypot Lab
  cert_sans:
    - honeypot.local
    - app1.honeypot.local
    - localhost
  routes:
    - method: ANY
      path: /
      response:
        status: 200
        headers:
          X-Test: https-ok
        body: "HTTPS OK"
`)

	cves, err := config.LoadDir(dir)
	require.NoError(t, err)
	require.Len(t, cves, 1)

	cve := cves[0]
	require.Equal(t, "https", cve.Protocol)
	require.NotNil(t, cve.HTTPS)
	require.Equal(t, "honeypot.local", cve.HTTPS.CertCN)
	require.Equal(t, "Honeypot Lab", cve.HTTPS.CertOrg)
	require.Equal(t, []string{"honeypot.local", "app1.honeypot.local", "localhost"}, cve.HTTPS.CertSANs)
	require.Len(t, cve.HTTPS.Routes, 1)
	r := cve.HTTPS.Routes[0]
	require.Equal(t, "ANY", r.Method)
	require.Equal(t, "/", r.Path)
	require.Equal(t, 200, r.Response.Status)
	require.Equal(t, "https-ok", r.Response.Headers["X-Test"])
}

// TestLoadDir_ParsesHTTPRouteHostField verifies that the optional host field
// on an HTTP route survives the YAML round-trip.
func TestLoadDir_ParsesHTTPRouteHostField(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "TEST-VHOST.yaml", `
id: TEST-VHOST
name: Vhost test
protocol: http
port: 80
http:
  routes:
    - method: ANY
      path: /
      host: app1.honeypot.local
      response:
        status: 200
        body: "app1-content"
    - method: ANY
      path: /
      response:
        status: 200
        body: "wildcard-content"
`)

	cves, err := config.LoadDir(dir)
	require.NoError(t, err)
	require.Len(t, cves, 1)

	routes := cves[0].HTTP.Routes
	require.Len(t, routes, 2)
	require.Equal(t, "app1.honeypot.local", routes[0].Host)
	require.Equal(t, "", routes[1].Host)
}

// TestLoadDir_ExistingConfigsBackwardCompat verifies that existing CVE configs
// without host or https fields still load correctly.
func TestLoadDir_ExistingConfigsBackwardCompat(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "CVE-2010-0738.yaml", `
id: CVE-2010-0738
name: JBoss Test
protocol: http
port: 80
http:
  routes:
    - method: HEAD
      path: /jmx-console/
      response:
        status: 200
        headers:
          Content-Type: text/html
          Server: Apache-Coyote/1.1 JBoss/5.0
        body: ""
`)

	cves, err := config.LoadDir(dir)
	require.NoError(t, err)
	require.Len(t, cves, 1)
	require.Nil(t, cves[0].HTTPS)
	require.Equal(t, "", cves[0].HTTP.Routes[0].Host)
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
}
