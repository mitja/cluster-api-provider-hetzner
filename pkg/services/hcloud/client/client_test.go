/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package hcloudclient_test

import (
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	hcloudclient "github.com/syself/cluster-api-provider-hetzner/pkg/services/hcloud/client"
)

const serverTypesResponse = `{"server_types": [], "meta": {"pagination": {"page": 1, "per_page": 50, "previous_page": null, "next_page": null, "last_page": 1, "total_entries": 0}}}`

func TestNewClientUsesEndpointFromEnv(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, serverTypesResponse)
	}))
	defer srv.Close()

	// Surrounding whitespace and a trailing slash are ignored.
	t.Setenv(hcloudclient.EndpointEnvVar, " "+srv.URL+"/v1/ ")

	c := hcloudclient.NewFactory().NewClient("my-token")
	_, err := c.ListServerTypes(context.Background())
	require.NoError(t, err)
	require.Equal(t, "/v1/server_types", gotPath)
	require.Equal(t, "Bearer my-token", gotAuth)
}

// recordingTransport answers every request itself, so the default endpoint is never contacted.
type recordingTransport struct {
	urls []string
}

func (rt *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.urls = append(rt.urls, req.URL.Scheme+"://"+req.URL.Host+req.URL.Path)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(serverTypesResponse)),
		Request:    req,
	}, nil
}

func TestNewClientUsesDefaultEndpointWithoutEnv(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value *string
	}{
		{name: "unset", value: nil},
		{name: "empty", value: ptr("")},
		{name: "whitespace only", value: ptr("  ")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// t.Setenv restores the previous value after the test, also after the Unsetenv below.
			t.Setenv(hcloudclient.EndpointEnvVar, "")
			if tc.value == nil {
				require.NoError(t, os.Unsetenv(hcloudclient.EndpointEnvVar))
			} else {
				t.Setenv(hcloudclient.EndpointEnvVar, *tc.value)
			}

			// The client's http.Client has no transport of its own, so it uses http.DefaultTransport.
			rt := &recordingTransport{}
			orig := http.DefaultTransport
			http.DefaultTransport = rt
			t.Cleanup(func() { http.DefaultTransport = orig })

			c := hcloudclient.NewFactory().NewClient("my-token")
			_, err := c.ListServerTypes(context.Background())
			require.NoError(t, err)
			require.Equal(t, []string{"https://api.hetzner.cloud/v1/server_types"}, rt.urls)
		})
	}
}

func ptr(s string) *string {
	return &s
}

// serverTypesServer returns a plain HTTP server that answers ListServerTypes and counts the calls.
func serverTypesServer(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, serverTypesResponse)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestNewClientEndpointOption(t *testing.T) {
	fromEnv, envCalls := serverTypesServer(t)
	fromOption, optionCalls := serverTypesServer(t)
	t.Setenv(hcloudclient.EndpointEnvVar, fromEnv.URL+"/v1")

	t.Run("the option wins over HCLOUD_ENDPOINT", func(t *testing.T) {
		*envCalls, *optionCalls = 0, 0
		c := hcloudclient.NewFactory().NewClient("my-token", hcloudclient.WithEndpoint(" "+fromOption.URL+"/v1 "))
		_, err := c.ListServerTypes(context.Background())
		require.NoError(t, err)
		require.Equal(t, 1, *optionCalls)
		require.Equal(t, 0, *envCalls)
	})

	t.Run("an empty option falls back to HCLOUD_ENDPOINT", func(t *testing.T) {
		*envCalls, *optionCalls = 0, 0
		c := hcloudclient.NewFactory().NewClient("my-token", hcloudclient.WithEndpoint("  "))
		_, err := c.ListServerTypes(context.Background())
		require.NoError(t, err)
		require.Equal(t, 0, *optionCalls)
		require.Equal(t, 1, *envCalls)
	})
}

func TestNewClientCABundleFromHTTPTestServer(t *testing.T) {
	var calls int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, serverTypesResponse)
	}))
	defer srv.Close()
	// The httptest certificate is self-signed, so it is its own CA.
	caBundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})

	f := hcloudclient.NewFactory()

	withoutCA := f.NewClient("my-token", hcloudclient.WithEndpoint(srv.URL+"/v1"))
	_, err := withoutCA.ListServerTypes(context.Background())
	require.ErrorContains(t, err, "certificate")
	require.Equal(t, 0, calls)

	withCA := f.NewClient("my-token", hcloudclient.WithEndpoint(srv.URL+"/v1"), hcloudclient.WithCABundle(caBundle))
	_, err = withCA.ListServerTypes(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, calls)
}

func TestValidateEndpoint(t *testing.T) {
	for _, tc := range []struct {
		endpoint string
		wantErr  bool
	}{
		{endpoint: ""},
		{endpoint: "  "},
		{endpoint: "https://api.hetzner.cloud/v1"},
		{endpoint: " https://192.168.64.1:19683/v1/ "},
		{endpoint: "http://localhost:8080/v1"},
		{endpoint: "api.hetzner.cloud/v1", wantErr: true},
		{endpoint: "ftp://api.hetzner.cloud/v1", wantErr: true},
		{endpoint: "https:///v1", wantErr: true},
		{endpoint: "https://api.hetzner.cloud/%zz", wantErr: true},
	} {
		t.Run(tc.endpoint, func(t *testing.T) {
			err := hcloudclient.ValidateEndpoint(tc.endpoint)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestParseCABundle(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})

	for _, tc := range []struct {
		name      string
		bundle    []byte
		wantCerts int
		wantErr   string
	}{
		{name: "empty", bundle: nil},
		{name: "blank", bundle: []byte(" \n\t")},
		{name: "one certificate", bundle: cert, wantCerts: 1},
		{name: "two certificates with blanks around", bundle: append(append([]byte("\n"), cert...), append([]byte("\n\n"), cert...)...), wantCerts: 2},
		{name: "comments around certificates", bundle: append(append([]byte("# CA one\n"), cert...), []byte("# end\n")...), wantCerts: 1},
		{name: "not PEM", bundle: []byte("not a certificate"), wantErr: "no PEM-encoded certificate found"},
		{name: "private key", bundle: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}), wantErr: `type "PRIVATE KEY"`},
		{name: "broken certificate", bundle: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}), wantErr: "invalid CA bundle"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certs, err := hcloudclient.ParseCABundle(tc.bundle)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Len(t, certs, tc.wantCerts)
		})
	}
}
