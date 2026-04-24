package server_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/RootEvidence/honeypot/config"
	"github.com/RootEvidence/honeypot/server"
	"github.com/stretchr/testify/require"
)

// cve builds a minimal HTTP CVE config for tests.
func cve(id string, routes []config.HTTPRoute) *config.CVE {
	return &config.CVE{
		ID:       id,
		Protocol: "http",
		Port:     80,
		HTTP:     &config.HTTPConfig{Routes: routes},
	}
}

func route(method, path string, status int, headers map[string]string, body string) config.HTTPRoute {
	return config.HTTPRoute{
		Method: method,
		Path:   path,
		Response: config.HTTPResponse{
			Status:  status,
			Headers: headers,
			Body:    body,
		},
	}
}

// TestServer_MatchesByPrefixAndMethod covers the core dispatch logic.
func TestServer_MatchesByPrefixAndMethod(t *testing.T) {
	tests := []struct {
		name           string
		routes         []config.HTTPRoute
		method         string
		path           string
		wantStatus     int
		wantBodyContains string
	}{
		{
			name: "exact_prefix_GET",
			routes: []config.HTTPRoute{
				route("GET", "/jmx-console/", 401, nil, "auth required"),
			},
			method:           "GET",
			path:             "/jmx-console/",
			wantStatus:       401,
			wantBodyContains: "auth required",
		},
		{
			name: "prefix_match_longer_path",
			routes: []config.HTTPRoute{
				route("GET", "/scripts/setup.php", 200, nil, "phpMyAdmin"),
			},
			method:           "GET",
			path:             "/scripts/setup.php?extra=1",
			wantStatus:       200,
			wantBodyContains: "phpMyAdmin",
		},
		{
			name: "ANY_method_matches_POST",
			routes: []config.HTTPRoute{
				route("ANY", "/_search", 200, nil, `{"test_calc":{"value":[98]}}`),
			},
			method:           "POST",
			path:             "/_search",
			wantStatus:       200,
			wantBodyContains: "test_calc",
		},
		{
			name: "wrong_method_returns_404",
			routes: []config.HTTPRoute{
				route("HEAD", "/jmx-console/", 200, nil, ""),
			},
			method:     "GET",
			path:       "/jmx-console/",
			wantStatus: 404,
		},
		{
			name:       "no_routes_returns_404",
			routes:     nil,
			method:     "GET",
			path:       "/anything",
			wantStatus: 404,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := server.New(80, []*config.CVE{cve("TEST-001", tt.routes)}, zap.NewNop(), "")

			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)

			require.Equal(t, tt.wantStatus, rec.Code)
			if tt.wantBodyContains != "" {
				body, _ := io.ReadAll(rec.Body)
				require.Contains(t, string(body), tt.wantBodyContains)
			}
		})
	}
}

// TestServer_HEADResponseHasNoBody confirms RFC 9110 compliance — the server
// must not send a body for HEAD even when the config has one configured.
func TestServer_HEADResponseHasNoBody(t *testing.T) {
	srv := server.New(80, []*config.CVE{
		cve("CVE-2010-0738", []config.HTTPRoute{
			route("HEAD", "/jmx-console/", 200,
				map[string]string{"Content-Type": "text/html", "Server": "JBoss/5.0"},
				"should not appear"),
		}),
	}, zap.NewNop(), "")

	req := httptest.NewRequest(http.MethodHead, "/jmx-console/", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, 200, rec.Code)
	require.Equal(t, "text/html", rec.Header().Get("Content-Type"))
	require.Equal(t, "JBoss/5.0", rec.Header().Get("Server"))
	require.Empty(t, rec.Body.String())
}

// TestServer_FirstRouteWinsOnPrefixConflict verifies that when two routes share
// a path prefix, the longer (more specific) path wins. Routes are sorted by
// length at construction time, so the longer path always takes precedence.
func TestServer_FirstRouteWinsOnPrefixConflict(t *testing.T) {
	srv := server.New(80, []*config.CVE{
		cve("CVE-TEST", []config.HTTPRoute{
			route("GET", "/scripts/setup.php", 200, nil, "first"),
			route("GET", "/scripts/", 200, nil, "second"),
		}),
	}, zap.NewNop(), "")

	req := httptest.NewRequest(http.MethodGet, "/scripts/setup.php", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	body, _ := io.ReadAll(rec.Body)
	require.Equal(t, "first", string(body))
}

// TestServer_RoutesSortedByLongestPathFirst verifies that the server matches by
// longest path even when the shorter route appears first in the config. This
// prevents /scripts/ from stealing /scripts/setup.php regardless of load order.
func TestServer_RoutesSortedByLongestPathFirst(t *testing.T) {
	// Deliberately register the shorter route first — sort must fix ordering.
	srv := server.New(80, []*config.CVE{
		cve("CVE-TEST", []config.HTTPRoute{
			route("GET", "/scripts/", 200, nil, "short"),
			route("GET", "/scripts/setup.php", 200, nil, "long"),
		}),
	}, zap.NewNop(), "")

	req := httptest.NewRequest(http.MethodGet, "/scripts/setup.php", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	body, _ := io.ReadAll(rec.Body)
	require.Equal(t, "long", string(body))
}

// TestServer_IgnoresTCPConfig confirms non-HTTP CVEs contribute no routes.
func TestServer_IgnoresTCPConfig(t *testing.T) {
	tcpCVE := &config.CVE{
		ID:       "CVE-2024-6387",
		Protocol: "tcp",
		Port:     22,
		TCP:      &config.TCPConfig{Banner: "SSH-2.0-OpenSSH_9.6p1\r\n"},
	}

	srv := server.New(80, []*config.CVE{tcpCVE}, zap.NewNop(), "")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, 404, rec.Code)
}

// TestServer_CVE2010_0738_MatcherSatisfied verifies the JBoss template matchers:
// HEAD /jmx-console/ → status 200, Content-Type contains "text/html", Server contains "JBoss".
func TestServer_CVE2010_0738_MatcherSatisfied(t *testing.T) {
	srv := server.New(80, []*config.CVE{
		cve("CVE-2010-0738", []config.HTTPRoute{
			route("HEAD", "/jmx-console/", 200,
				map[string]string{
					"Content-Type": "text/html; charset=UTF-8",
					"Server":       "Apache-Coyote/1.1 JBoss/5.0",
				}, ""),
		}),
	}, zap.NewNop(), "")

	req := httptest.NewRequest(http.MethodHead, "/jmx-console/", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, 200, rec.Code)
	require.Contains(t, rec.Header().Get("Content-Type"), "text/html")
	require.Contains(t, rec.Header().Get("Server"), "JBoss")
}

// TestServer_CVE2012_1823_MatcherSatisfied verifies the PHP CGI matcher:
// body contains the expected md5 hash.
func TestServer_CVE2012_1823_MatcherSatisfied(t *testing.T) {
	const md5Hash = "3d638155445bffb044eec401381ad784"

	srv := server.New(80, []*config.CVE{
		cve("CVE-2012-1823", []config.HTTPRoute{
			route("POST", "/index.php", 200, nil, md5Hash),
		}),
	}, zap.NewNop(), "")

	req := httptest.NewRequest(http.MethodPost, "/index.php?-d+allow_url_include%3don", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, 200, rec.Code)
	body, _ := io.ReadAll(rec.Body)
	require.Contains(t, string(body), md5Hash)
}

// TestServer_ExactMatchDoesNotCatchAll verifies that a route with match:"exact"
// on "/" does not absorb longer paths. Without exact matching, "/" is a prefix
// of every path, causing false positives for any GET request.
func TestServer_ExactMatchDoesNotCatchAll(t *testing.T) {
	srv := server.New(80, []*config.CVE{
		cve("CVE-2014-3120", []config.HTTPRoute{
			{Method: "GET", Path: "/", Match: "exact", Response: config.HTTPResponse{Status: 200, Body: "es-root"}},
			{Method: "POST", Path: "/_search", Response: config.HTTPResponse{Status: 200, Body: "search-result"}},
		}),
	}, zap.NewNop(), "")

	// Exact match: GET / → 200
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)

	// Non-matching: GET /random → 404 (no longer caught by the "/" route)
	req2 := httptest.NewRequest(http.MethodGet, "/random/path", nil)
	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, req2)
	require.Equal(t, 404, rec2.Code)

	// Prefix still works for /_search: POST /_search?pretty → 200
	req3 := httptest.NewRequest(http.MethodPost, "/_search?pretty", nil)
	rec3 := httptest.NewRecorder()
	srv.ServeHTTP(rec3, req3)
	require.Equal(t, 200, rec3.Code)
}

// TestServer_CVE2014_3120_TwoStepMatcherSatisfied verifies that the ES cluster
// info route and _search route both return the expected fields.
func TestServer_CVE2014_3120_TwoStepMatcherSatisfied(t *testing.T) {
	srv := server.New(80, []*config.CVE{
		cve("CVE-2014-3120", []config.HTTPRoute{
			route("GET", "/", 200,
				map[string]string{"Content-Type": "application/json"},
				`{"cluster_name":"elasticsearch","version":{"number":"1.1.1"}}`),
			route("POST", "/_search", 200,
				map[string]string{"Content-Type": "application/json"},
				`{"script_fields":{"test_calc":{"value":[98]}}}`),
		}),
	}, zap.NewNop(), "")

	// Step 1: cluster info
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	rec1 := httptest.NewRecorder()
	srv.ServeHTTP(rec1, req1)
	require.Equal(t, 200, rec1.Code)
	body1, _ := io.ReadAll(rec1.Body)
	require.Contains(t, string(body1), "cluster_name")
	require.Contains(t, string(body1), "1.1.1")

	// Step 2: _search returns test_calc and 98
	req2 := httptest.NewRequest(http.MethodPost, "/_search?pretty", nil)
	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, req2)
	require.Equal(t, 200, rec2.Code)
	body2, _ := io.ReadAll(rec2.Body)
	require.Contains(t, string(body2), "test_calc")
	require.Contains(t, string(body2), "98")
}

// oastRoute builds an HTTPRoute with an OAST callback config.
func oastRoute(method, path string, cfg *config.OASTCallbackConfig, status int, body string) config.HTTPRoute {
	return config.HTTPRoute{
		Method:       method,
		Path:         path,
		OASTCallback: cfg,
		Response:     config.HTTPResponse{Status: status, Body: body},
	}
}

// echoRoute builds an HTTPRoute that echoes a regex capture group as the body.
func echoRoute(method, path, extractRegex string) config.HTTPRoute {
	return config.HTTPRoute{
		Method: method,
		Path:   path,
		Response: config.HTTPResponse{
			Status: 200,
			Echo:   &config.EchoConfig{ExtractRegex: extractRegex},
		},
	}
}

// TestServer_OASTCallback_FiresHTTPGet verifies that when a route has an
// oast_callback config the server fires an outbound GET to the oastTarget with
// the Host header set to the hostname parsed from the extracted interactsh URL.
// The main response must still be returned regardless of callback outcome.
func TestServer_OASTCallback_FiresHTTPGet(t *testing.T) {
	// Capture the outbound OAST request. Mutex guards gotHost/gotMethod because
	// the httptest handler runs in a separate goroutine.
	var mu sync.Mutex
	var gotHost, gotMethod string
	callbackSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotHost = r.Host
		gotMethod = r.Method
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(callbackSrv.Close)

	// Strip the leading "http://" to get host:port for oastTarget.
	oastTarget := callbackSrv.Listener.Addr().String()

	srv := server.New(80, []*config.CVE{
		cve("CVE-2015-2051", []config.HTTPRoute{
			oastRoute("POST", "/HNAP1/",
				&config.OASTCallbackConfig{
					ExtractFrom:  "header",
					HeaderName:   "SOAPAction",
					ExtractRegex: `wget\s+(https?://\S+[^` + "`" + `"\s])`,
				},
				200, "<ModelName>DIR-645</ModelName>"),
		}),
	}, zap.NewNop(), oastTarget)

	req := httptest.NewRequest(http.MethodPost, "/HNAP1/",
		strings.NewReader(`<soap:Envelope/>`))
	req.Header.Set("SOAPAction", "wget http://abc123.honeypot.local")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	// Main response must be correct.
	require.Equal(t, 200, rec.Code)
	body, _ := io.ReadAll(rec.Body)
	require.Contains(t, string(body), "DIR-645")

	// Give the goroutine time to complete the outbound request.
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return gotHost != ""
	}, 2*time.Second, 10*time.Millisecond)

	mu.Lock()
	wantHost, wantMethod := gotHost, gotMethod
	mu.Unlock()
	require.Equal(t, http.MethodGet, wantMethod)
	require.Equal(t, "abc123.honeypot.local", wantHost)
}

// TestServer_OASTCallback_NonBlocking confirms that an unreachable oastTarget
// does not delay the HTTP response.
func TestServer_OASTCallback_NonBlocking(t *testing.T) {
	srv := server.New(80, []*config.CVE{
		cve("CVE-TEST", []config.HTTPRoute{
			oastRoute("POST", "/HNAP1/",
				&config.OASTCallbackConfig{
					ExtractFrom:  "header",
					HeaderName:   "SOAPAction",
					ExtractRegex: `wget\s+(https?://\S+)`,
				},
				200, "ok"),
		}),
	}, zap.NewNop(), "localhost:1") // port 1 is unreachable

	start := time.Now()
	req := httptest.NewRequest(http.MethodPost, "/HNAP1/", nil)
	req.Header.Set("SOAPAction", "wget http://abc123.honeypot.local")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	// Response must come back immediately — well under the 5s callback timeout.
	require.Less(t, time.Since(start), time.Second)
	require.Equal(t, 200, rec.Code)
}

// TestServer_EchoResponse_ExtractsAndReturns verifies that when a route has an
// echo config the extracted capture group is used as the response body.
func TestServer_EchoResponse_ExtractsAndReturns(t *testing.T) {
	srv := server.New(80, []*config.CVE{
		cve("CVE-TEST", []config.HTTPRoute{
			echoRoute("POST", "/echo", `<string>([^<]+)</string>`),
		}),
	}, zap.NewNop(), "")

	req := httptest.NewRequest(http.MethodPost, "/echo",
		strings.NewReader(`<root><string>extracted-value</string></root>`))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, 200, rec.Code)
	body, _ := io.ReadAll(rec.Body)
	require.Equal(t, "extracted-value", string(body))
}

// TestServer_EchoResponse_NoMatchReturns404 verifies that echo extraction
// failure returns 404 rather than an empty body.
func TestServer_EchoResponse_NoMatchReturns404(t *testing.T) {
	srv := server.New(80, []*config.CVE{
		cve("CVE-TEST", []config.HTTPRoute{
			echoRoute("POST", "/echo", `<string>([^<]+)</string>`),
		}),
	}, zap.NewNop(), "")

	req := httptest.NewRequest(http.MethodPost, "/echo",
		strings.NewReader(`no match here`))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, 404, rec.Code)
}

// TestServer_CVE2015_2051_MatcherSatisfied loads the CVE-2015-2051 config and
// verifies the response body satisfies Nuclei's positive matchers and avoids
// the negative anti-echo matchers.
func TestServer_CVE2015_2051_MatcherSatisfied(t *testing.T) {
	srv := server.New(80, []*config.CVE{
		cve("CVE-2015-2051", []config.HTTPRoute{
			oastRoute("POST", "/HNAP1/", nil, 200,
				`<?xml version="1.0" encoding="utf-8"?>
<GetDeviceSettingsResponse>
<ModelName>DIR-645</ModelName>
<ModelDescription>D-Link Wireless Router</ModelDescription>
<FirmwareVersion>1.04b12</FirmwareVersion>
<HardwareVersion>A1</HardwareVersion>
</GetDeviceSettingsResponse>`),
		}),
	}, zap.NewNop(), "")

	req := httptest.NewRequest(http.MethodPost, "/HNAP1/", nil)
	req.Header.Set("SOAPAction", `"http://purenetworks.com/HNAP1/GetDeviceSettings"`)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, 200, rec.Code)
	body, _ := io.ReadAll(rec.Body)
	bodyStr := string(body)

	// Positive matchers.
	require.Contains(t, bodyStr, "ModelName")
	require.Contains(t, bodyStr, "ModelDescription")
	require.Contains(t, bodyStr, "FirmwareVersion")
	require.Contains(t, bodyStr, "HardwareVersion")

	// Negative (anti-echo) matchers — body must NOT contain these.
	require.NotContains(t, bodyStr, "soap:Envelope")
	require.NotContains(t, bodyStr, "purenetworks.com/HNAP1")
	require.NotContains(t, bodyStr, "GetDeviceSettings xmlns")
}

// TestServer_CVE2017_10271_EchoMatcherSatisfied verifies that the echo route
// returns the randstr token verbatim with status 200, satisfying the template's
// body == randstr matcher.
func TestServer_CVE2017_10271_EchoMatcherSatisfied(t *testing.T) {
	srv := server.New(80, []*config.CVE{
		cve("CVE-2017-10271", []config.HTTPRoute{
			echoRoute("POST", "/wls-wsat/CoordinatorPortType",
				`<void method="write"><string>([^<]+)</string></void>`),
		}),
	}, zap.NewNop(), "")

	const randstr = "t3stR4nd0mStr1ng"
	reqBody := `<soapenv:Envelope><soapenv:Body>` +
		`<void method="write"><string>` + randstr + `</string></void>` +
		`</soapenv:Body></soapenv:Envelope>`

	req := httptest.NewRequest(http.MethodPost, "/wls-wsat/CoordinatorPortType",
		strings.NewReader(reqBody))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, 200, rec.Code)
	body, _ := io.ReadAll(rec.Body)
	require.Equal(t, randstr, string(body))
}

// --- Vhost routing tests ---

// hostCVE builds a minimal HTTP CVE with a host-filtered route for tests.
func hostCVE(id, host, body string) *config.CVE {
	return &config.CVE{
		ID:       id,
		Protocol: "http",
		Port:     80,
		HTTP: &config.HTTPConfig{
			Routes: []config.HTTPRoute{
				{
					Method: "ANY",
					Path:   "/",
					Host:   host,
					Response: config.HTTPResponse{
						Status: 200,
						Body:   body,
					},
				},
			},
		},
	}
}

// TestServer_VhostRoute_MatchesOnHostHeader verifies that a route with a Host
// field only responds to requests whose Host header matches.
func TestServer_VhostRoute_MatchesOnHostHeader(t *testing.T) {
	srv := server.New(80, []*config.CVE{
		hostCVE("TEST-VHOST", "app1.honeypot.local", "app1-content"),
	}, zap.NewNop(), "")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "app1.honeypot.local"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, 200, rec.Code)
	body, _ := io.ReadAll(rec.Body)
	require.Equal(t, "app1-content", string(body))
}

// TestServer_VhostRoute_SkipsOnHostMismatch verifies that a route with a Host
// field does not match requests with a different Host header.
func TestServer_VhostRoute_SkipsOnHostMismatch(t *testing.T) {
	srv := server.New(80, []*config.CVE{
		hostCVE("TEST-VHOST", "app1.honeypot.local", "app1-content"),
	}, zap.NewNop(), "")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "app2.honeypot.local"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	// No match — the only route is for app1, not app2.
	require.Equal(t, 404, rec.Code)
}

// TestServer_VhostRoute_WildcardMatchesAnyHost verifies that a route without a
// Host field matches regardless of the Host header value.
func TestServer_VhostRoute_WildcardMatchesAnyHost(t *testing.T) {
	srv := server.New(80, []*config.CVE{
		{
			ID:       "TEST-WILDCARD",
			Protocol: "http",
			Port:     80,
			HTTP: &config.HTTPConfig{
				Routes: []config.HTTPRoute{
					{Method: "ANY", Path: "/", Response: config.HTTPResponse{Status: 200, Body: "wildcard"}},
				},
			},
		},
	}, zap.NewNop(), "")

	for _, host := range []string{"app1.honeypot.local", "app2.honeypot.local", "anything.example.com"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		require.Equal(t, 200, rec.Code, "host: %s", host)
	}
}

// TestServer_VhostRoute_HostSpecificWinsOverWildcard verifies that a
// host-specific route takes priority over a wildcard route at the same path length.
func TestServer_VhostRoute_HostSpecificWinsOverWildcard(t *testing.T) {
	srv := server.New(80, []*config.CVE{
		{
			ID:       "TEST-PRIORITY",
			Protocol: "http",
			Port:     80,
			HTTP: &config.HTTPConfig{
				Routes: []config.HTTPRoute{
					// Register wildcard first — sort must promote host-specific.
					{Method: "ANY", Path: "/", Response: config.HTTPResponse{Status: 200, Body: "wildcard"}},
					{Method: "ANY", Path: "/", Host: "app1.honeypot.local", Response: config.HTTPResponse{Status: 200, Body: "app1"}},
				},
			},
		},
	}, zap.NewNop(), "")

	// app1 request → host-specific route wins.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "app1.honeypot.local"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)
	body, _ := io.ReadAll(rec.Body)
	require.Equal(t, "app1", string(body))

	// other host → wildcard matches.
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Host = "other.honeypot.local"
	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, req2)
	require.Equal(t, 200, rec2.Code)
	body2, _ := io.ReadAll(rec2.Body)
	require.Equal(t, "wildcard", string(body2))
}

// TestServer_VhostRoute_StripPortFromHostHeader verifies that the port suffix
// in a Host header (e.g., "app1.honeypot.local:8080") is stripped before
// matching against the route's host field.
func TestServer_VhostRoute_StripPortFromHostHeader(t *testing.T) {
	srv := server.New(80, []*config.CVE{
		hostCVE("TEST-VHOST-PORT", "app1.honeypot.local", "app1-content"),
	}, zap.NewNop(), "")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "app1.honeypot.local:8080"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, 200, rec.Code)
	body, _ := io.ReadAll(rec.Body)
	require.Equal(t, "app1-content", string(body))
}

// TestServer_VhostAndCVERoutesCoexist verifies that a CVE route with a specific
// path still matches when vhost routes on "/" exist for port 80 — the longer
// path wins regardless of host.
func TestServer_VhostAndCVERoutesCoexist(t *testing.T) {
	srv := server.New(80, []*config.CVE{
		// CVE route: specific path, no host filter.
		{
			ID:       "CVE-2010-0738",
			Protocol: "http",
			Port:     80,
			HTTP: &config.HTTPConfig{
				Routes: []config.HTTPRoute{
					route("HEAD", "/jmx-console/", 200,
						map[string]string{"Server": "JBoss/5.0"}, ""),
				},
			},
		},
		// Vhost route: "/" with host filter.
		hostCVE("TEST-VHOST", "app1.honeypot.local", "app1-content"),
	}, zap.NewNop(), "")

	// CVE route still matches.
	req := httptest.NewRequest(http.MethodHead, "/jmx-console/", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)
	require.Equal(t, "JBoss/5.0", rec.Header().Get("Server"))

	// Vhost route also works.
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Host = "app1.honeypot.local"
	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, req2)
	require.Equal(t, 200, rec2.Code)
	body2, _ := io.ReadAll(rec2.Body)
	require.Equal(t, "app1-content", string(body2))
}

// --- HTTPS server tests ---

// TestHTTPS_ServesTLSConnection verifies that NewHTTPS creates a server that
// accepts TLS connections and serves HTTP responses over TLS.
func TestHTTPS_ServesTLSConnection(t *testing.T) {
	httpsCVE := &config.CVE{
		ID:       "TEST-HTTPS-443",
		Protocol: "https",
		Port:     443,
		HTTPS: &config.HTTPSConfig{
			CertCN:  "honeypot.local",
			CertOrg: "Honeypot Lab",
			Routes: []config.HTTPRoute{
				{Method: "ANY", Path: "/", Response: config.HTTPResponse{Status: 200, Body: "HTTPS OK"}},
			},
		},
	}

	srv, err := server.NewHTTPS(443, []*config.CVE{httpsCVE}, zap.NewNop(), "")
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go srv.StartOnListener(ctx, ln) //nolint:errcheck

	tlsCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	addr := ln.Addr().String()
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, tlsCfg)
			},
		},
	}
	resp, err := httpClient.Get("https://" + addr + "/")
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, "HTTPS OK", string(body))
}

// TestHTTPS_CertHasCorrectCNAndSANs verifies that the TLS certificate presented
// by the HTTPS server has the CN and SANs from the config.
func TestHTTPS_CertHasCorrectCNAndSANs(t *testing.T) {
	httpsCSV := &config.CVE{
		ID:       "TEST-HTTPS-CERT",
		Protocol: "https",
		Port:     443,
		HTTPS: &config.HTTPSConfig{
			CertCN:   "honeypot.local",
			CertOrg:  "Honeypot Lab",
			CertSANs: []string{"honeypot.local", "app1.honeypot.local", "localhost"},
			Routes:   []config.HTTPRoute{},
		},
	}

	srv, err := server.NewHTTPS(443, []*config.CVE{httpsCSV}, zap.NewNop(), "")
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go srv.StartOnListener(ctx, ln) //nolint:errcheck

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
	require.Equal(t, "honeypot.local", leaf.Subject.CommonName)
	require.Contains(t, leaf.Subject.Organization, "Honeypot Lab")

	// SANs should include all configured values.
	require.Contains(t, leaf.DNSNames, "honeypot.local")
	require.Contains(t, leaf.DNSNames, "app1.honeypot.local")
	require.Contains(t, leaf.DNSNames, "localhost")
}

// TestHTTPS_DefaultSANsWhenNoneConfigured verifies that when cert_sans is empty
// the server defaults to [certCN, "honeypot", "honeypot.local", "localhost"].
func TestHTTPS_DefaultSANsWhenNoneConfigured(t *testing.T) {
	httpsCSV := &config.CVE{
		ID:       "TEST-HTTPS-DEFAULTS",
		Protocol: "https",
		Port:     443,
		HTTPS: &config.HTTPSConfig{
			CertCN:  "my-service.local",
			CertOrg: "Test Org",
			// No CertSANs — expect defaults.
			Routes: []config.HTTPRoute{},
		},
	}

	srv, err := server.NewHTTPS(443, []*config.CVE{httpsCSV}, zap.NewNop(), "")
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go srv.StartOnListener(ctx, ln) //nolint:errcheck

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
	require.Contains(t, leaf.DNSNames, "my-service.local")
	require.Contains(t, leaf.DNSNames, "honeypot")
	require.Contains(t, leaf.DNSNames, "honeypot.local")
	require.Contains(t, leaf.DNSNames, "localhost")
}

// TestHTTPS_VhostRoutingOverTLS verifies that host-filtered routes work the
// same over HTTPS as they do over plain HTTP.
func TestHTTPS_VhostRoutingOverTLS(t *testing.T) {
	httpsCSV := &config.CVE{
		ID:       "TEST-VHOST-HTTPS",
		Protocol: "https",
		Port:     443,
		HTTPS: &config.HTTPSConfig{
			CertCN:  "honeypot.local",
			CertOrg: "Honeypot Lab",
			Routes: []config.HTTPRoute{
				{Method: "ANY", Path: "/", Host: "app1.honeypot.local", Response: config.HTTPResponse{Status: 200, Body: "app1-https"}},
				{Method: "ANY", Path: "/", Host: "app2.honeypot.local", Response: config.HTTPResponse{Status: 200, Body: "app2-https"}},
			},
		},
	}

	srv, err := server.NewHTTPS(443, []*config.CVE{httpsCSV}, zap.NewNop(), "")
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go srv.StartOnListener(ctx, ln) //nolint:errcheck

	addr := ln.Addr().String()
	tlsCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec

	makeReq := func(host string) *http.Response {
		t.Helper()
		client := &http.Client{
			Transport: &http.Transport{
				DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, tlsCfg)
				},
			},
		}
		req, err := http.NewRequest(http.MethodGet, "https://"+addr+"/", nil)
		require.NoError(t, err)
		req.Host = host
		resp, err := client.Do(req)
		require.NoError(t, err)
		return resp
	}

	resp1 := makeReq("app1.honeypot.local")
	defer resp1.Body.Close()
	b1, _ := io.ReadAll(resp1.Body)
	require.Equal(t, "app1-https", string(b1))

	resp2 := makeReq("app2.honeypot.local")
	defer resp2.Body.Close()
	b2, _ := io.ReadAll(resp2.Body)
	require.Equal(t, "app2-https", string(b2))
}
