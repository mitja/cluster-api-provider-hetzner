/*
Copyright 2022 The Kubernetes Authors.

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

// Package hcloudclient defines and implements the interface for talking to Hetzner HCloud API.
package hcloudclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	caphversion "github.com/syself/cluster-api-provider-hetzner/pkg/version"
)

const errStringUnauthorized = "(unauthorized)"

// ErrUnauthorized means that the API call is unauthorized.
var ErrUnauthorized = fmt.Errorf("unauthorized")

// Client collects all methods used by the controller in the hcloud cloud API.
type Client interface {
	CreateLoadBalancer(context.Context, hcloud.LoadBalancerCreateOpts) (*hcloud.LoadBalancer, error)
	DeleteLoadBalancer(context.Context, int64) error
	ListLoadBalancers(context.Context, hcloud.LoadBalancerListOpts) ([]*hcloud.LoadBalancer, error)
	AttachLoadBalancerToNetwork(context.Context, *hcloud.LoadBalancer, hcloud.LoadBalancerAttachToNetworkOpts) error
	ChangeLoadBalancerType(context.Context, *hcloud.LoadBalancer, hcloud.LoadBalancerChangeTypeOpts) error
	ChangeLoadBalancerAlgorithm(context.Context, *hcloud.LoadBalancer, hcloud.LoadBalancerChangeAlgorithmOpts) error
	UpdateLoadBalancer(context.Context, *hcloud.LoadBalancer, hcloud.LoadBalancerUpdateOpts) (*hcloud.LoadBalancer, error)
	AddTargetServerToLoadBalancer(context.Context, hcloud.LoadBalancerAddServerTargetOpts, *hcloud.LoadBalancer) error
	DeleteTargetServerOfLoadBalancer(context.Context, *hcloud.LoadBalancer, *hcloud.Server) error
	AddIPTargetToLoadBalancer(context.Context, hcloud.LoadBalancerAddIPTargetOpts, *hcloud.LoadBalancer) error
	DeleteIPTargetOfLoadBalancer(context.Context, *hcloud.LoadBalancer, net.IP) error
	AddServiceToLoadBalancer(context.Context, *hcloud.LoadBalancer, hcloud.LoadBalancerAddServiceOpts) error
	UpdateServiceOnLoadBalancer(context.Context, *hcloud.LoadBalancer, int, hcloud.LoadBalancerUpdateServiceOpts) error
	DeleteServiceFromLoadBalancer(context.Context, *hcloud.LoadBalancer, int) error
	ListImages(context.Context, hcloud.ImageListOpts) ([]*hcloud.Image, error)
	CreateServer(context.Context, hcloud.ServerCreateOpts) (hcloud.ServerCreateResult, error)
	AttachServerToNetwork(context.Context, *hcloud.Server, hcloud.ServerAttachToNetworkOpts) error
	ListServers(context.Context, hcloud.ServerListOpts) ([]*hcloud.Server, error)
	GetServer(context.Context, int64) (*hcloud.Server, error)
	DeleteServer(context.Context, *hcloud.Server) error
	ListServerTypes(context.Context) ([]*hcloud.ServerType, error)
	GetServerType(context.Context, string) (*hcloud.ServerType, error)
	PowerOnServer(context.Context, *hcloud.Server) error
	ShutdownServer(context.Context, *hcloud.Server) error
	RebootServer(context.Context, *hcloud.Server) error
	CreateNetwork(context.Context, hcloud.NetworkCreateOpts) (*hcloud.Network, error)
	ListNetworks(context.Context, hcloud.NetworkListOpts) ([]*hcloud.Network, error)
	DeleteNetwork(context.Context, *hcloud.Network) error
	ListSSHKeys(context.Context, hcloud.SSHKeyListOpts) ([]*hcloud.SSHKey, error)
	CreatePlacementGroup(context.Context, hcloud.PlacementGroupCreateOpts) (*hcloud.PlacementGroup, error)
	DeletePlacementGroup(context.Context, int64) error
	ListPlacementGroups(context.Context, hcloud.PlacementGroupListOpts) ([]*hcloud.PlacementGroup, error)
	AddServerToPlacementGroup(context.Context, *hcloud.Server, *hcloud.PlacementGroup) error

	EnableRescueSystem(context.Context, *hcloud.Server, *hcloud.ServerEnableRescueOpts) (hcloud.ServerEnableRescueResult, error)

	Reboot(context.Context, *hcloud.Server) (*hcloud.Action, error)

	GetAction(ctx context.Context, actionID int64) (*hcloud.Action, error)
}

// Factory is the interface for creating new Client objects.
type Factory interface {
	// NewClient returns a new Client in the real implementation, and the shared global Client in the fake implementation.
	NewClient(hcloudToken string, opts ...ClientOption) Client
}

// ClientOption configures a Client that a Factory creates.
type ClientOption func(*clientOptions)

type clientOptions struct {
	endpoint string
	caBundle []byte
}

// WithEndpoint sets the endpoint of the HCloud API, for example "https://api.hetzner.cloud/v1".
// Surrounding whitespace is ignored. An empty endpoint leaves the default: the environment variable
// HCLOUD_ENDPOINT if it is set, else the default endpoint of hcloud-go. Callers should check the
// value with ValidateEndpoint first.
func WithEndpoint(endpoint string) ClientOption {
	return func(o *clientOptions) {
		o.endpoint = strings.TrimSpace(endpoint)
	}
}

// WithCABundle adds PEM-encoded CA certificates to the system roots that the client trusts. They
// apply to this client only. An empty (or blank) bundle leaves the system roots alone. Callers
// should check the bundle with ParseCABundle first: a client built with an invalid bundle fails
// every request.
func WithCABundle(caBundle []byte) ClientOption {
	return func(o *clientOptions) {
		o.caBundle = bytes.TrimSpace(caBundle)
	}
}

// ValidateEndpoint checks that endpoint is an absolute http or https URL. An empty (or blank)
// endpoint is valid and means the default.
func ValidateEndpoint(endpoint string) error {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return nil
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid HCloud API endpoint %q: %w", endpoint, err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("invalid HCloud API endpoint %q: want an absolute http or https URL", endpoint)
	}
	return nil
}

// ParseCABundle parses PEM-encoded CA certificates. Every PEM block must be a certificate that
// parses, and at least one is required. Text outside of PEM blocks (comments, as in system bundles)
// is ignored. An empty (or blank) bundle returns (nil, nil).
func ParseCABundle(caBundle []byte) ([]*x509.Certificate, error) {
	rest := bytes.TrimSpace(caBundle)
	if len(rest) == 0 {
		return nil, nil
	}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("invalid CA bundle: PEM block of type %q, want CERTIFICATE", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("invalid CA bundle: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("invalid CA bundle: no PEM-encoded certificate found")
	}
	return certs, nil
}

// LoggingTransport is a struct for creating new logger for hcloud API.
type LoggingTransport struct {
	roundTripper http.RoundTripper
	hcloudToken  string
}

var replaceHex = regexp.MustCompile(`0x[0123456789abcdef]+`)

// RoundTrip is used for logging api calls to hcloud API.
func (lt *LoggingTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	stack := replaceHex.ReplaceAllString(string(debug.Stack()), "0xX")
	resp, err = lt.roundTripper.RoundTrip(req)
	token := lt.hcloudToken[:5] + "..."
	logger := ctrl.LoggerFrom(req.Context()).WithName("hcloud-api")
	req.Context()
	if err != nil {
		logger.V(1).Info("hcloud API called. Error.", "err", err, "method", req.Method, "url", req.URL, "hcloud_token", token, "stack", stack)
		return resp, err
	}
	logger.V(1).Info("hcloud API called", "statusCode", resp.StatusCode, "method", req.Method, "url", req.URL, "hcloud_token", token, "stack", stack)
	return resp, nil
}

// DebugAPICalls loggs all hcloud API calls if true.
var DebugAPICalls bool

// EndpointEnvVar is the environment variable that sets the endpoint of the HCloud API. If it is
// unset or empty, the default endpoint of hcloud-go (https://api.hetzner.cloud/v1) is used. The
// hcloud CLI and the hcloud cloud controller manager read the same variable.
const EndpointEnvVar = "HCLOUD_ENDPOINT"

// NewClient creates new HCloud clients.
//
// The endpoint is the one from WithEndpoint, else HCLOUD_ENDPOINT, else the default of hcloud-go.
// A CA bundle from WithCABundle is trusted in addition to the system roots, by this client only.
func (f *factory) NewClient(hcloudToken string, opts ...ClientOption) Client {
	var o clientOptions
	for _, opt := range opts {
		opt(&o)
	}

	httpClient := &http.Client{}
	if len(o.caBundle) > 0 {
		httpClient.Transport = f.transportFor(o.caBundle)
	}

	hcloudOpts := []hcloud.ClientOption{
		hcloud.WithToken(hcloudToken),
		hcloud.WithApplication("cluster-api-provider-hetzner", caphversion.Get().String()),
		hcloud.WithInstrumentation(metrics.Registry),
		hcloud.WithHTTPClient(httpClient),
	}
	endpoint := o.endpoint
	if endpoint == "" {
		endpoint = strings.TrimSpace(os.Getenv(EndpointEnvVar))
	}
	if endpoint != "" {
		hcloudOpts = append(hcloudOpts, hcloud.WithEndpoint(endpoint))
	}

	hcloudClient := realClient{client: hcloud.NewClient(hcloudOpts...)}
	if DebugAPICalls {
		roundTripper := httpClient.Transport
		if roundTripper == nil {
			roundTripper = http.DefaultTransport
		}
		httpClient.Transport = &LoggingTransport{
			roundTripper: roundTripper,
			hcloudToken:  hcloudToken,
		}
	}
	return &hcloudClient
}

// transportFor returns the transport that trusts the system roots plus caBundle. Transports are
// cached by the bundle's hash: clients are created per reconcile, and a new transport each time
// would throw away its connection pool and do a new TLS handshake for every reconcile.
func (f *factory) transportFor(caBundle []byte) http.RoundTripper {
	key := sha256.Sum256(caBundle)

	f.mu.Lock()
	defer f.mu.Unlock()
	if rt, ok := f.transports[key]; ok {
		return rt
	}
	rt := newCABundleTransport(caBundle)
	if f.transports == nil {
		f.transports = make(map[[sha256.Size]byte]http.RoundTripper)
	}
	f.transports[key] = rt
	return rt
}

// newCABundleTransport clones http.DefaultTransport and makes it trust the system roots plus
// caBundle. If caBundle is invalid, the returned transport fails every request.
func newCABundleTransport(caBundle []byte) http.RoundTripper {
	certs, err := ParseCABundle(caBundle)
	if err != nil {
		return errorTransport{err: err}
	}
	pool, err := systemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	for _, cert := range certs {
		pool.AddCert(cert)
	}

	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return errorTransport{err: errors.New("http.DefaultTransport is not an *http.Transport")}
	}
	transport := base.Clone()
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	transport.TLSClientConfig.RootCAs = pool
	return transport
}

// systemCertPool returns a copy of the system roots. Tests replace it.
var systemCertPool = x509.SystemCertPool

// errorTransport fails every request with err.
type errorTransport struct {
	err error
}

func (t errorTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, t.err
}

type factory struct {
	mu         sync.Mutex
	transports map[[sha256.Size]byte]http.RoundTripper
}

var _ = Factory(&factory{})

// NewFactory creates a new factory for HCloud clients.
func NewFactory() Factory {
	return &factory{}
}

var _ Client = &realClient{}

type realClient struct {
	client *hcloud.Client
}

func (c *realClient) CreateLoadBalancer(ctx context.Context, opts hcloud.LoadBalancerCreateOpts) (*hcloud.LoadBalancer, error) {
	res, _, err := c.client.LoadBalancer.Create(ctx, opts)
	return res.LoadBalancer, err
}

func (c *realClient) DeleteLoadBalancer(ctx context.Context, id int64) error {
	_, err := c.client.LoadBalancer.Delete(ctx, &hcloud.LoadBalancer{ID: id})
	return err
}

func (c *realClient) ListLoadBalancers(ctx context.Context, opts hcloud.LoadBalancerListOpts) ([]*hcloud.LoadBalancer, error) {
	resp, err := c.client.LoadBalancer.AllWithOpts(ctx, opts)
	if err != nil && strings.Contains(err.Error(), errStringUnauthorized) {
		return resp, fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}
	return resp, err
}

func (c *realClient) AttachLoadBalancerToNetwork(ctx context.Context, lb *hcloud.LoadBalancer, opts hcloud.LoadBalancerAttachToNetworkOpts) error {
	_, _, err := c.client.LoadBalancer.AttachToNetwork(ctx, lb, opts)
	return err
}

func (c *realClient) ChangeLoadBalancerType(ctx context.Context, lb *hcloud.LoadBalancer, opts hcloud.LoadBalancerChangeTypeOpts) error {
	_, _, err := c.client.LoadBalancer.ChangeType(ctx, lb, opts)
	return err
}

func (c *realClient) ChangeLoadBalancerAlgorithm(ctx context.Context, lb *hcloud.LoadBalancer, opts hcloud.LoadBalancerChangeAlgorithmOpts) error {
	_, _, err := c.client.LoadBalancer.ChangeAlgorithm(ctx, lb, opts)
	return err
}

func (c *realClient) UpdateLoadBalancer(ctx context.Context, lb *hcloud.LoadBalancer, opts hcloud.LoadBalancerUpdateOpts) (*hcloud.LoadBalancer, error) {
	res, _, err := c.client.LoadBalancer.Update(ctx, lb, opts)
	return res, err
}

func (c *realClient) AddTargetServerToLoadBalancer(ctx context.Context, opts hcloud.LoadBalancerAddServerTargetOpts, lb *hcloud.LoadBalancer) error {
	_, _, err := c.client.LoadBalancer.AddServerTarget(ctx, lb, opts)
	return err
}

func (c *realClient) AddIPTargetToLoadBalancer(ctx context.Context, opts hcloud.LoadBalancerAddIPTargetOpts, lb *hcloud.LoadBalancer) error {
	_, _, err := c.client.LoadBalancer.AddIPTarget(ctx, lb, opts)
	if err != nil && strings.Contains(err.Error(), errStringUnauthorized) {
		return fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}
	return err
}

func (c *realClient) DeleteTargetServerOfLoadBalancer(ctx context.Context, lb *hcloud.LoadBalancer, server *hcloud.Server) error {
	_, _, err := c.client.LoadBalancer.RemoveServerTarget(ctx, lb, server)
	if err != nil && strings.Contains(err.Error(), errStringUnauthorized) {
		return fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}
	return err
}

func (c *realClient) DeleteIPTargetOfLoadBalancer(ctx context.Context, lb *hcloud.LoadBalancer, ip net.IP) error {
	_, _, err := c.client.LoadBalancer.RemoveIPTarget(ctx, lb, ip)
	if err != nil && strings.Contains(err.Error(), errStringUnauthorized) {
		return fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}
	return err
}

func (c *realClient) AddServiceToLoadBalancer(ctx context.Context, lb *hcloud.LoadBalancer, opts hcloud.LoadBalancerAddServiceOpts) error {
	_, _, err := c.client.LoadBalancer.AddService(ctx, lb, opts)
	return err
}

func (c *realClient) UpdateServiceOnLoadBalancer(ctx context.Context, lb *hcloud.LoadBalancer, listenPort int, opts hcloud.LoadBalancerUpdateServiceOpts) error {
	_, _, err := c.client.LoadBalancer.UpdateService(ctx, lb, listenPort, opts)
	return err
}

func (c *realClient) DeleteServiceFromLoadBalancer(ctx context.Context, lb *hcloud.LoadBalancer, listenPort int) error {
	_, _, err := c.client.LoadBalancer.DeleteService(ctx, lb, listenPort)
	return err
}

func (c *realClient) ListImages(ctx context.Context, opts hcloud.ImageListOpts) ([]*hcloud.Image, error) {
	return c.client.Image.AllWithOpts(ctx, opts)
}

func (c *realClient) CreateServer(ctx context.Context, opts hcloud.ServerCreateOpts) (hcloud.ServerCreateResult, error) {
	res, _, err := c.client.Server.Create(ctx, opts)
	return res, err
}

func (c *realClient) AttachServerToNetwork(ctx context.Context, server *hcloud.Server, opts hcloud.ServerAttachToNetworkOpts) error {
	_, _, err := c.client.Server.AttachToNetwork(ctx, server, opts)
	return err
}

func (c *realClient) ListServers(ctx context.Context, opts hcloud.ServerListOpts) ([]*hcloud.Server, error) {
	resp, err := c.client.Server.AllWithOpts(ctx, opts)
	if err != nil && strings.Contains(err.Error(), errStringUnauthorized) {
		return resp, fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}
	return resp, err
}

// GetServer retrieves a server by its ID.
// It returns both server and error as nil when the server does not exist, as hcloud-go's GetByID
// returns nil for non-existent server without an error.
func (c *realClient) GetServer(ctx context.Context, id int64) (*hcloud.Server, error) {
	res, _, err := c.client.Server.GetByID(ctx, id)
	if err != nil && strings.Contains(err.Error(), errStringUnauthorized) {
		return res, fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}
	return res, err
}

func (c *realClient) ListServerTypes(ctx context.Context) ([]*hcloud.ServerType, error) {
	resp, err := c.client.ServerType.All(ctx)
	if err != nil && strings.Contains(err.Error(), errStringUnauthorized) {
		return resp, fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}
	return resp, err
}

func (c *realClient) GetServerType(ctx context.Context, name string) (*hcloud.ServerType, error) {
	res, _, err := c.client.ServerType.GetByName(ctx, name)
	if err != nil && strings.Contains(err.Error(), errStringUnauthorized) {
		return res, fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}
	return res, err
}

func (c *realClient) ShutdownServer(ctx context.Context, server *hcloud.Server) error {
	_, _, err := c.client.Server.Shutdown(ctx, server)
	return err
}

func (c *realClient) RebootServer(ctx context.Context, server *hcloud.Server) error {
	_, _, err := c.client.Server.Reboot(ctx, server)
	return err
}

func (c *realClient) PowerOnServer(ctx context.Context, server *hcloud.Server) error {
	_, _, err := c.client.Server.Poweron(ctx, server)
	if err != nil && strings.Contains(err.Error(), errStringUnauthorized) {
		return fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}
	return err
}

func (c *realClient) DeleteServer(ctx context.Context, server *hcloud.Server) error {
	_, _, err := c.client.Server.DeleteWithResult(ctx, server)
	return err
}

func (c *realClient) CreateNetwork(ctx context.Context, opts hcloud.NetworkCreateOpts) (*hcloud.Network, error) {
	res, _, err := c.client.Network.Create(ctx, opts)
	return res, err
}

func (c *realClient) ListNetworks(ctx context.Context, opts hcloud.NetworkListOpts) ([]*hcloud.Network, error) {
	resp, err := c.client.Network.AllWithOpts(ctx, opts)
	if err != nil && strings.Contains(err.Error(), errStringUnauthorized) {
		return resp, fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}
	return resp, err
}

func (c *realClient) DeleteNetwork(ctx context.Context, network *hcloud.Network) error {
	_, err := c.client.Network.Delete(ctx, network)
	return err
}

func (c *realClient) ListSSHKeys(ctx context.Context, opts hcloud.SSHKeyListOpts) ([]*hcloud.SSHKey, error) {
	res, _, err := c.client.SSHKey.List(ctx, opts)
	return res, err
}

func (c *realClient) CreatePlacementGroup(ctx context.Context, opts hcloud.PlacementGroupCreateOpts) (*hcloud.PlacementGroup, error) {
	res, _, err := c.client.PlacementGroup.Create(ctx, opts)
	return res.PlacementGroup, err
}

func (c *realClient) DeletePlacementGroup(ctx context.Context, id int64) error {
	_, err := c.client.PlacementGroup.Delete(ctx, &hcloud.PlacementGroup{ID: id})
	return err
}

func (c *realClient) ListPlacementGroups(ctx context.Context, opts hcloud.PlacementGroupListOpts) ([]*hcloud.PlacementGroup, error) {
	return c.client.PlacementGroup.AllWithOpts(ctx, opts)
}

func (c *realClient) AddServerToPlacementGroup(ctx context.Context, server *hcloud.Server, pg *hcloud.PlacementGroup) error {
	_, _, err := c.client.Server.AddToPlacementGroup(ctx, server, pg)
	return err
}

func (c *realClient) EnableRescueSystem(ctx context.Context, server *hcloud.Server, rescueOpts *hcloud.ServerEnableRescueOpts) (result hcloud.ServerEnableRescueResult, reterr error) {
	result, _, err := c.client.Server.EnableRescue(ctx, server, *rescueOpts)
	if err != nil {
		if strings.Contains(err.Error(), errStringUnauthorized) {
			return result, fmt.Errorf("%w: EnableRescue failed for %d: %w", ErrUnauthorized, server.ID, err)
		}
		return result, fmt.Errorf("EnableRescue failed for %d: %w", server.ID, err)
	}
	return result, nil
}

func (c *realClient) Reboot(ctx context.Context, server *hcloud.Server) (*hcloud.Action, error) {
	action, _, err := c.client.Server.Reboot(ctx, server)
	if err != nil {
		return action, fmt.Errorf("Reboot failed for %d: %w", server.ID, err)
	}
	return action, nil
}

func (c *realClient) GetAction(ctx context.Context, actionID int64) (*hcloud.Action, error) {
	action, _, err := c.client.Action.GetByID(ctx, actionID)
	if err != nil {
		if strings.Contains(err.Error(), errStringUnauthorized) {
			return action, fmt.Errorf("%w: getting hcloud action failed: %w", ErrUnauthorized, err)
		}
		return action, fmt.Errorf("getting hcloud action failed: %w", err)
	}
	// GetByID returns a nil action and no error when the action does not exist.
	// Return an error instead, so callers can rely on the action being non-nil when err is nil.
	if action == nil {
		return nil, fmt.Errorf("hcloud action %d not found", actionID)
	}
	return action, nil
}
