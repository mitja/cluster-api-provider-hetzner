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

package controllers

import (
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/klog/v2"
	conditions "sigs.k8s.io/cluster-api/util/conditions"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	infrav2 "github.com/syself/cluster-api-provider-hetzner/api/v1beta2"
	secretutil "github.com/syself/cluster-api-provider-hetzner/pkg/secrets"
	hcloudclient "github.com/syself/cluster-api-provider-hetzner/pkg/services/hcloud/client"
)

const testServerTypesResponse = `{"server_types": [], "meta": {"pagination": {"page": 1, "per_page": 50, "previous_page": null, "next_page": null, "last_page": 1, "total_entries": 0}}}`

// newServerTypesServer starts a server that answers ListServerTypes and counts the calls.
func newServerTypesServer(t *testing.T, useTLS bool) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, testServerTypesResponse)
	})
	var srv *httptest.Server
	if useTLS {
		srv = httptest.NewTLSServer(handler)
	} else {
		srv = httptest.NewServer(handler)
	}
	t.Cleanup(srv.Close)
	return srv, &calls
}

// TestHCloudClientOptions checks which HCloud API the client for a cluster talks to, depending on
// the endpoint and CA bundle keys of its Hetzner secret.
func TestHCloudClientOptions(t *testing.T) {
	// The secret's endpoint: TLS with the self-signed httptest certificate, its own CA.
	secretSrv, secretCalls := newServerTypesServer(t, true)
	caBundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: secretSrv.Certificate().Raw})
	// The process-wide fallback, HCLOUD_ENDPOINT.
	envSrv, envCalls := newServerTypesServer(t, false)

	for _, tc := range []struct {
		name        string
		data        map[string][]byte
		endpointKey string
		caBundleKey string
		env         string
		wantErr     string
		wantSecret  int
		wantEnv     int
		wantTLSErr  bool
	}{
		{
			name:       "endpoint and CA bundle under the default keys",
			data:       map[string][]byte{"hcloud-endpoint": []byte(secretSrv.URL + "/v1"), "hcloud-ca-bundle": caBundle},
			env:        envSrv.URL + "/v1",
			wantSecret: 1,
		},
		{
			name:        "endpoint and CA bundle under custom keys",
			data:        map[string][]byte{"url": []byte(secretSrv.URL + "/v1\n"), "ca.crt": caBundle},
			endpointKey: "url",
			caBundleKey: "ca.crt",
			wantSecret:  1,
		},
		{
			name:        "keys named in the spec but not in the secret fall back to HCLOUD_ENDPOINT",
			data:        map[string][]byte{"hcloud-endpoint": []byte(secretSrv.URL + "/v1"), "hcloud-ca-bundle": caBundle},
			endpointKey: "url",
			caBundleKey: "ca.crt",
			env:         envSrv.URL + "/v1",
			wantEnv:     1,
		},
		{
			name:    "no keys in the secret fall back to HCLOUD_ENDPOINT",
			data:    map[string][]byte{},
			env:     envSrv.URL + "/v1",
			wantEnv: 1,
		},
		{
			name:    "empty values fall back to HCLOUD_ENDPOINT",
			data:    map[string][]byte{"hcloud-endpoint": {}, "hcloud-ca-bundle": {}},
			env:     envSrv.URL + "/v1",
			wantEnv: 1,
		},
		{
			name:       "endpoint without CA bundle does not trust the private CA",
			data:       map[string][]byte{"hcloud-endpoint": []byte(secretSrv.URL + "/v1")},
			wantTLSErr: true,
		},
		{
			name:    "invalid CA bundle",
			data:    map[string][]byte{"hcloud-endpoint": []byte(secretSrv.URL + "/v1"), "hcloud-ca-bundle": []byte("not a certificate")},
			wantErr: `key "hcloud-ca-bundle": invalid CA bundle`,
		},
		{
			name:    "invalid endpoint",
			data:    map[string][]byte{"hcloud-endpoint": []byte("hcloud.example.com/v1")},
			wantErr: `key "hcloud-endpoint": invalid HCloud API endpoint`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(hcloudclient.EndpointEnvVar, tc.env)
			if tc.env == "" {
				require.NoError(t, os.Unsetenv(hcloudclient.EndpointEnvVar))
			}
			*secretCalls, *envCalls = 0, 0

			secret := &corev1.Secret{Data: tc.data}
			opts, err := hcloudClientOptions(secret, tc.endpointKey, tc.caBundleKey)
			if tc.wantErr != "" {
				var validationErr *secretutil.HCloudEndpointValidationError
				require.ErrorAs(t, err, &validationErr)
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)

			_, err = hcloudclient.NewFactory().NewClient("my-token", opts...).ListServerTypes(context.Background())
			if tc.wantTLSErr {
				require.ErrorContains(t, err, "certificate")
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.wantSecret, *secretCalls, "calls to the secret's endpoint")
			require.Equal(t, tc.wantEnv, *envCalls, "calls to HCLOUD_ENDPOINT")
		})
	}
}

// TestGetAndValidateHCloudTokenInvalidCABundle checks that an invalid CA bundle in the Hetzner
// secret sets HCloudTokenAvailable to false with the reason, like an invalid token.
func TestGetAndValidateHCloudTokenInvalidCABundle(t *testing.T) {
	ctx := context.Background()

	testScheme := runtime.NewScheme()
	utilruntime.Must(corev1.AddToScheme(testScheme))
	utilruntime.Must(infrav2.AddToScheme(testScheme))

	hetznerCluster := &infrav2.HetznerCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "test-cluster", Namespace: "test-ns", UID: "test-cluster-uid"},
		Spec:       getDefaultHetznerClusterSpec(),
	}
	hetznerCluster.Spec.HetznerSecret.Name = "hetzner"
	hetznerCluster.Spec.HetznerSecret.Key.HCloudToken = "hcloud-token"

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "hetzner", Namespace: "test-ns"},
		Data: map[string][]byte{
			"hcloud-token":     []byte("my-token"),
			"hcloud-endpoint":  []byte("https://hcloud.example.com/v1"),
			"hcloud-ca-bundle": []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
		},
	}

	c := fakeclient.NewClientBuilder().
		WithScheme(testScheme).
		WithObjects(hetznerCluster.DeepCopy(), secret).
		WithStatusSubresource(&infrav2.HetznerCluster{}).
		Build()
	secretManager := secretutil.NewSecretManager(klog.Background(), c, c)

	token, opts, gotSecret, err := getAndValidateHCloudToken(ctx, "test-ns", hetznerCluster, secretManager)
	require.Empty(t, token)
	require.Nil(t, opts)
	require.Nil(t, gotSecret)
	var validationErr *secretutil.HCloudEndpointValidationError
	require.ErrorAs(t, err, &validationErr)

	require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(hetznerCluster), hetznerCluster))
	res, resErr := hcloudTokenErrorResult(ctx, err, hetznerCluster, c, nil)
	require.Equal(t, err, resErr, "returned like an invalid token")
	require.Zero(t, res)

	cond := conditions.Get(hetznerCluster, infrav2.HCloudTokenAvailableCondition)
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, infrav2.HCloudTokenInvalidReason, cond.Reason)
	require.Contains(t, cond.Message, `key "hcloud-ca-bundle": invalid CA bundle`)

	// With a valid bundle, the token and two options come back.
	require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(secret), secret))
	secret.Data["hcloud-ca-bundle"] = nil
	require.NoError(t, c.Update(ctx, secret))
	token, opts, gotSecret, err = getAndValidateHCloudToken(ctx, "test-ns", hetznerCluster, secretManager)
	require.NoError(t, err)
	require.Equal(t, "my-token", token)
	require.Len(t, opts, 1, "the endpoint only, the CA bundle is empty")
	require.NotNil(t, gotSecret)
}
