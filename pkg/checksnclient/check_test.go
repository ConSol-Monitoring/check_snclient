package checksnclient

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheck(t *testing.T) {
	ctx := t.Context()
	buf := &bytes.Buffer{}

	exitCode := Check(ctx, buf, []string{"-h"}, nil)
	assert.Equal(t, 3, exitCode)
	assert.Contains(t, buf.String(), "Usage:")

	buf.Reset()
	exitCode = Check(ctx, buf, []string{"-p", "password", "-u", "http://localhost:12345", "check_cpu"}, nil)
	assert.Equal(t, 3, exitCode)
	assert.Contains(t, buf.String(), "UNKNOWN")
	assert.Contains(t, buf.String(), "connect:")
	assert.NotContains(t, buf.String(), "check_cpu")
}

func TestCheckConfig(t *testing.T) {
	ctx := t.Context()
	buf := &bytes.Buffer{}
	tmpFile := filepath.Join(t.TempDir(), "config")

	config := `
# test config file
k true
p password
u https://127.0.0.1:12345
query check_cpu show-all
`
	err := os.WriteFile(tmpFile, []byte(config), 0o600)
	require.NoError(t, err)

	exitCode := Check(ctx, buf, []string{"-config", tmpFile}, nil)
	assert.Equal(t, 3, exitCode)
	assert.Contains(t, buf.String(), "UNKNOWN")
	assert.Contains(t, buf.String(), "connect:")
	assert.NotContains(t, buf.String(), "check_cpu")
}

func TestFormatPerfValue(t *testing.T) {
	// Integer values must not be rounded or padded with decimals.
	assert.Equal(t, "10", formatPerfValue(10, 2))
	assert.Equal(t, "10", formatPerfValue(10, -1))

	// Float values are rounded to the configured number of digits.
	assert.Equal(t, "10.50", formatPerfValue(10.5, 2))
	assert.Equal(t, "10.5", formatPerfValue(10.5, -1))
	assert.Equal(t, "12.35", formatPerfValue(12.3456, 2))
}

func TestParseEnvironmentVariables(t *testing.T) {
	// The new check_snclient_* names.
	flags := &flagSet{}
	parseEnvironmentVariables(flags, []string{
		"check_snclient_password=newpass",
		"CHECK_SNCLIENT_LOGIN=newlogin",
		"check_snclient_timeout=30",
		"CHECK_SNCLIENT_PROXY=http://proxy:8080",
	})
	assert.Equal(t, "newpass", flags.Password)
	assert.Equal(t, "newlogin", flags.Login)
	assert.Equal(t, "30", flags.Timeout)
	assert.Equal(t, "http://proxy:8080", flags.Proxy)

	// The check_snclient_proxy_url alias.
	flags = &flagSet{}
	parseEnvironmentVariables(flags, []string{
		"check_snclient_proxy_url=http://proxy-url:8080",
	})
	assert.Equal(t, "http://proxy-url:8080", flags.Proxy)

	// The deprecated check_nsc_web_* names must keep working.
	flags = &flagSet{}
	parseEnvironmentVariables(flags, []string{
		"check_nsc_web_password=oldpass",
		"CHECK_NSC_WEB_LOGIN=oldlogin",
		"check_nsc_web_timeout=60",
		"check_nsc_web_proxy=http://oldproxy:8080",
	})
	assert.Equal(t, "oldpass", flags.Password)
	assert.Equal(t, "oldlogin", flags.Login)
	assert.Equal(t, "60", flags.Timeout)
	assert.Equal(t, "http://oldproxy:8080", flags.Proxy)
}

func TestBuildRequestTimeoutHeader(t *testing.T) {
	ctx := t.Context()
	buf := &bytes.Buffer{}

	flags := &flagSet{Timeout: "5:UNKNOWN", Password: "secret"}
	req, err := buildRequest(ctx, buf, "https://127.0.0.1:8443/", flags)
	require.NoError(t, err)

	// The new header name is sent, and the legacy name is kept for
	// backwards compatibility with older servers.
	assert.Equal(t, "5.00", req.Header.Get("X-Snclient-Timeout"))
	assert.Equal(t, "5.00", req.Header.Get("X-Nsc-Web-Timeout"))
}

func TestGetProxyFunc(t *testing.T) {
	dummyReq, _ := http.NewRequest(http.MethodGet, "http://target.example.com", http.NoBody)

	// empty / none / direct
	for _, val := range []string{"", "none", "NONE", "direct", "DIRECT"} {
		fn, err := getProxyFunc(val)
		require.NoError(t, err)
		assert.Nil(t, fn)
	}

	// env
	t.Setenv("HTTP_PROXY", "http://envproxy:8080")
	fn, err := getProxyFunc("env")
	require.NoError(t, err)
	require.NotNil(t, fn)
	proxyURL, err := fn(dummyReq)
	require.NoError(t, err)
	require.NotNil(t, proxyURL)
	assert.Equal(t, "http://envproxy:8080", proxyURL.String())

	// standard URL
	fn, err = getProxyFunc("http://127.0.0.1:8080")
	require.NoError(t, err)
	require.NotNil(t, fn)
	proxyURL, err = fn(dummyReq)
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:8080", proxyURL.String())

	// URL with credentials
	fn, err = getProxyFunc("http://user:secret@127.0.0.1:8080")
	require.NoError(t, err)
	require.NotNil(t, fn)
	proxyURL, err = fn(dummyReq)
	require.NoError(t, err)
	assert.Equal(t, "http://user:secret@127.0.0.1:8080", proxyURL.String())

	// auto-prepend http://
	fn, err = getProxyFunc("127.0.0.1:3128")
	require.NoError(t, err)
	require.NotNil(t, fn)
	proxyURL, err = fn(dummyReq)
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:3128", proxyURL.String())

	// socks5
	fn, err = getProxyFunc("socks5://127.0.0.1:1080")
	require.NoError(t, err)
	require.NotNil(t, fn)
	proxyURL, err = fn(dummyReq)
	require.NoError(t, err)
	assert.Equal(t, "socks5://127.0.0.1:1080", proxyURL.String())

	// unsupported scheme
	_, err = getProxyFunc("ftp://127.0.0.1:21")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported proxy scheme: ftp")

	// missing host
	_, err = getProxyFunc("http://")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing host")
}

func TestCheckWithProxy(t *testing.T) {
	ctx := t.Context()
	buf := &bytes.Buffer{}

	proxyHit := false
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHit = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"command":"check_cpu","result":0,"lines":[{"message":"OK - cpu 5%"}]}`))
	}))
	defer proxyServer.Close()

	exitCode := Check(ctx, buf, []string{
		"-u", "http://unreachable-host-example.test:8443",
		"-p", "secret",
		"-a", "1",
		"-proxy", proxyServer.URL,
		"check_cpu",
	}, nil)

	assert.True(t, proxyHit, "request must pass through proxy")
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, buf.String(), "OK - cpu 5%")
}
