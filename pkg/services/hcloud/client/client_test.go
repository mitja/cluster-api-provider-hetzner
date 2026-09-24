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
