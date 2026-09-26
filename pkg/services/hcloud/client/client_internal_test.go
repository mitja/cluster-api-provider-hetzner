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

package hcloudclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const serverTypesJSON = `{"server_types": [], "meta": {"pagination": {"page": 1, "per_page": 50, "previous_page": null, "next_page": null, "last_page": 1, "total_entries": 0}}}`

// testCA is a private CA that issues a certificate for 127.0.0.1 to a test server.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// newServer starts an HTTPS server with a certificate from ca that answers ListServerTypes.
func (ca *testCA) newServer(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)

	calls := 0
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, serverTypesJSON)
	}))
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &calls
}

// TestNewClientAddsCABundleToSystemRoots checks that a CA bundle is trusted in addition to the
// system roots (one client reaches a server with a publicly trusted certificate and one with a
// private CA), and only by the client it was given to.
func TestNewClientAddsCABundleToSystemRoots(t *testing.T) {
	publicCA := newTestCA(t, "stands in for a public CA")
	privateCA := newTestCA(t, "private CA")

	// Stand in for the system roots, so the test does not depend on the host's trust store.
	orig := systemCertPool
	systemCertPool = func() (*x509.CertPool, error) {
		pool := x509.NewCertPool()
		pool.AddCert(publicCA.cert)
		return pool, nil
	}
	t.Cleanup(func() { systemCertPool = orig })

	publicSrv, publicCalls := publicCA.newServer(t)
	privateSrv, privateCalls := privateCA.newServer(t)

	f := NewFactory()
	ctx := context.Background()

	// With the private CA's bundle: both the private and the "public" server are trusted.
	_, err := f.NewClient("token", WithEndpoint(privateSrv.URL+"/v1"), WithCABundle(privateCA.pem)).ListServerTypes(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, *privateCalls)

	_, err = f.NewClient("token", WithEndpoint(publicSrv.URL+"/v1"), WithCABundle(privateCA.pem)).ListServerTypes(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, *publicCalls)

	// With the public CA's bundle only, the private server is not trusted.
	_, err = f.NewClient("token", WithEndpoint(privateSrv.URL+"/v1"), WithCABundle(publicCA.pem)).ListServerTypes(ctx)
	require.ErrorContains(t, err, "certificate")
	require.Equal(t, 1, *privateCalls)
}

func TestTransportForCachesByCABundle(t *testing.T) {
	a := newTestCA(t, "a")
	b := newTestCA(t, "b")
	f := &factory{}

	rtA := f.transportFor(a.pem)
	require.Same(t, rtA, f.transportFor(append([]byte{}, a.pem...)), "same bundle, same transport")
	require.NotSame(t, rtA, f.transportFor(b.pem), "another bundle, another transport")
	require.Len(t, f.transports, 2)
}

func TestNewClientWithInvalidCABundleFailsEveryRequest(t *testing.T) {
	ca := newTestCA(t, "ca")
	srv, calls := ca.newServer(t)

	c := NewFactory().NewClient("token", WithEndpoint(srv.URL+"/v1"), WithCABundle([]byte("not a certificate")))
	_, err := c.ListServerTypes(context.Background())
	require.ErrorContains(t, err, "invalid CA bundle")
	require.Equal(t, 0, *calls)
}

func TestNewClientWithDebugAPICallsAndNoCABundle(t *testing.T) {
	ca := newTestCA(t, "ca")
	srv, _ := ca.newServer(t)

	DebugAPICalls = true
	t.Cleanup(func() { DebugAPICalls = false })

	// Without a CA bundle the logging transport wraps http.DefaultTransport, which does not trust
	// the test CA. The request must fail with a TLS error, not panic on a nil transport.
	_, err := NewFactory().NewClient("token-12345", WithEndpoint(srv.URL+"/v1")).ListServerTypes(context.Background())
	require.ErrorContains(t, err, "certificate")

	_, err = NewFactory().NewClient("token-12345", WithEndpoint(srv.URL+"/v1"), WithCABundle(ca.pem)).ListServerTypes(context.Background())
	require.NoError(t, err)
}
