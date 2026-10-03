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

// Package network implements the lifecycle of HCloud networks.
package network

import (
	"context"
	"fmt"
	"net"
	"slices"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clusterv1beta1 "sigs.k8s.io/cluster-api/api/core/v1beta1"
	v1beta1conditions "sigs.k8s.io/cluster-api/util/deprecated/v1beta1/conditions"
	v1beta2conditions "sigs.k8s.io/cluster-api/util/deprecated/v1beta1/conditions/v1beta2"
	"sigs.k8s.io/cluster-api/util/record"

	infrav1 "github.com/syself/cluster-api-provider-hetzner/api/v1beta1"
	"github.com/syself/cluster-api-provider-hetzner/pkg/scope"
	hcloudutil "github.com/syself/cluster-api-provider-hetzner/pkg/services/hcloud/util"
	"github.com/syself/cluster-api-provider-hetzner/pkg/utils"
)

// Service struct contains cluster scope to reconcile networks.
type Service struct {
	scope *scope.ClusterScope
}

// NewService creates a new service object.
func NewService(scope *scope.ClusterScope) *Service {
	return &Service{
		scope: scope,
	}
}

// Reconcile implements life cycle of networks.
func (s *Service) Reconcile(ctx context.Context) (err error) {
	// delete the deprecated condition from existing cluster objects
	v1beta1conditions.Delete(s.scope.HetznerCluster, infrav1.DeprecatedNetworkAttachedCondition)

	if !s.scope.HetznerCluster.Spec.HCloudNetwork.Enabled {
		return nil
	}

	defer func() {
		if err != nil {
			v1beta1conditions.MarkFalse(
				s.scope.HetznerCluster,
				infrav1.NetworkReadyCondition,
				infrav1.NetworkReconcileFailedReason,
				clusterv1beta1.ConditionSeverityWarning,
				"%s",
				err.Error(),
			)

			v1beta2conditions.Set(s.scope.HetznerCluster, metav1.Condition{
				Type:    infrav1.HetznerClusterNetworkReadyV1Beta2Condition,
				Status:  metav1.ConditionFalse,
				Reason:  infrav1.HetznerClusterNetworkReconcilingFailedV1Beta2Reason,
				Message: err.Error(),
			})
		}
	}()

	network, err := s.findNetwork(ctx)
	if err != nil {
		return fmt.Errorf("failed to find network: %w", err)
	}

	if network == nil {
		network, err = s.createNetwork(ctx)
		if err != nil {
			return fmt.Errorf("failed to create network: %w", err)
		}
	}

	v1beta1conditions.MarkTrue(s.scope.HetznerCluster, infrav1.NetworkReadyCondition)

	v1beta2conditions.Set(s.scope.HetznerCluster, metav1.Condition{
		Type:   infrav1.HetznerClusterNetworkReadyV1Beta2Condition,
		Status: metav1.ConditionTrue,
		Reason: string(infrav1.HetznerClusterNetworkReadyV1Beta2Reason),
	})

	s.scope.HetznerCluster.Status.Network = statusFromHCloudNetwork(network)

	return nil
}

func (s *Service) createNetwork(ctx context.Context) (*hcloud.Network, error) {
	opts, err := s.createOpts()
	if err != nil {
		return nil, fmt.Errorf("failed to create NetworkCreateOpts: %w", err)
	}

	resp, err := s.scope.HCloudClient.CreateNetwork(ctx, opts)
	if err != nil {
		hcloudutil.HandleRateLimitExceeded(s.scope.HetznerCluster, err, "CreateNetwork")
		record.Warnf(s.scope.HetznerCluster, "NetworkCreatedFailed", "Failed to create network with opts %s", opts)
		return nil, fmt.Errorf("failed to create network: %w", err)
	}

	record.Eventf(s.scope.HetznerCluster, "NetworkCreated", "Created network with opts %+v", opts)
	return resp, nil
}

func (s *Service) createOpts() (hcloud.NetworkCreateOpts, error) {
	spec := s.scope.HetznerCluster.Spec.HCloudNetwork

	_, network, err := net.ParseCIDR(spec.CIDRBlock)
	if err != nil {
		return hcloud.NetworkCreateOpts{}, fmt.Errorf("invalid network %q: %w", spec.CIDRBlock, err)
	}

	_, subnet, err := net.ParseCIDR(spec.SubnetCIDRBlock)
	if err != nil {
		return hcloud.NetworkCreateOpts{}, fmt.Errorf("invalid network %q: %w", spec.SubnetCIDRBlock, err)
	}

	return hcloud.NetworkCreateOpts{
		Name:    s.scope.HetznerCluster.Name,
		IPRange: network,
		Labels:  s.labels(),
		Subnets: []hcloud.NetworkSubnet{
			{
				IPRange:     subnet,
				NetworkZone: hcloud.NetworkZone(spec.NetworkZone),
				Type:        hcloud.NetworkSubnetTypeCloud,
			},
		},
	}, nil
}

// NetworkOwnerLabel marks a network that something other than this cluster owns. Such a network is shared:
// gardener-stack's HCloudGateway controller (components/hcloud-gateway) creates one network per NAT gateway, puts the
// gateway server on it and labels it caph-cluster-<name>=owned for every member cluster BEFORE that cluster exists, so
// CAPH adopts it (findNetwork) instead of creating one. Several clusters and the gateway live on it at once, so CAPH must
// never delete it with any one of them: on delete it only drops its own label and leaves the network to its owner.
// The value names the owner (the gateway); any value counts.
const NetworkOwnerLabel = "paasbox.com/network-owner"

// Delete implements deletion of the network. A network that names an owner (NetworkOwnerLabel) is released instead:
// this cluster's label is removed and the network stays.
func (s *Service) Delete(ctx context.Context) error {
	if s.scope.HetznerCluster.Status.Network == nil {
		// nothing to delete
		return nil
	}

	id := s.scope.HetznerCluster.Status.Network.ID

	// read the network fresh: the labels in the status are those of the last reconcile and may be stale
	network, err := s.scope.HCloudClient.GetNetwork(ctx, id)
	if err != nil {
		hcloudutil.HandleRateLimitExceeded(s.scope.HetznerCluster, err, "GetNetwork")
		if hcloud.IsError(err, hcloud.ErrorCodeNotFound) {
			s.scope.V(1).Info("deleting network failed - not found", "id", id)
			return nil
		}
		return fmt.Errorf("failed to get network %d: %w", id, err)
	}
	if network == nil {
		// if resource has been deleted already then do nothing
		s.scope.V(1).Info("deleting network failed - not found", "id", id)
		return nil
	}

	if owner, owned := network.Labels[NetworkOwnerLabel]; owned {
		return s.release(ctx, network, owner)
	}

	if err := s.scope.HCloudClient.DeleteNetwork(ctx, &hcloud.Network{ID: id}); err != nil {
		hcloudutil.HandleRateLimitExceeded(s.scope.HetznerCluster, err, "DeleteNetwork")
		// if resource has been deleted already then do nothing
		if hcloud.IsError(err, hcloud.ErrorCodeNotFound) {
			s.scope.V(1).Info("deleting network failed - not found", "id", id)
			return nil
		}
		record.Warnf(s.scope.HetznerCluster, "NetworkDeleteFailed", "Failed to delete network with ID %v", id)
		return fmt.Errorf("failed to delete network: %w", err)
	}

	record.Eventf(s.scope.HetznerCluster, "NetworkDeleted", "Deleted network with ID %v", id)
	return nil
}

// release removes this cluster's label from a network that has an owner, keeping every other label.
func (s *Service) release(ctx context.Context, network *hcloud.Network, owner string) error {
	key := s.scope.HetznerCluster.ClusterTagKey()
	if _, has := network.Labels[key]; !has {
		s.scope.V(1).Info("network has an owner and no label of this cluster - leaving it", "id", network.ID, "owner", owner)
		return nil
	}
	labels := make(map[string]string, len(network.Labels))
	for k, v := range network.Labels {
		if k != key {
			labels[k] = v
		}
	}
	if _, err := s.scope.HCloudClient.UpdateNetwork(ctx, network, hcloud.NetworkUpdateOpts{Labels: labels}); err != nil {
		hcloudutil.HandleRateLimitExceeded(s.scope.HetznerCluster, err, "UpdateNetwork")
		if hcloud.IsError(err, hcloud.ErrorCodeNotFound) {
			s.scope.V(1).Info("releasing network failed - not found", "id", network.ID)
			return nil
		}
		record.Warnf(s.scope.HetznerCluster, "NetworkReleaseFailed", "Failed to remove label %s from network with ID %v (owner %s)", key, network.ID, owner)
		return fmt.Errorf("failed to remove label %s from network %d: %w", key, network.ID, err)
	}

	record.Eventf(s.scope.HetznerCluster, "NetworkReleased",
		"Network with ID %v is owned by %q (%s): removed label %s, not deleted", network.ID, owner, NetworkOwnerLabel, key)
	return nil
}

func (s *Service) findNetwork(ctx context.Context) (*hcloud.Network, error) {
	opts := hcloud.NetworkListOpts{}
	opts.LabelSelector = utils.LabelsToLabelSelector(s.labels())

	networks, err := s.scope.HCloudClient.ListNetworks(ctx, opts)
	if err != nil {
		hcloudutil.HandleRateLimitExceeded(s.scope.HetznerCluster, err, "ListNetworks")
		return nil, fmt.Errorf("failed to list networks: %w", err)
	}

	if len(networks) > 1 {
		return nil, fmt.Errorf("found multiple networks with opts %v - not allowed", opts)
	}

	if len(networks) == 0 {
		return nil, nil
	}

	if len(networks[0].Subnets) >= 1 {
		// Allow existing subnets, but validate them

		// When multiple subnets of type "cloud" are present,
		// there currently is no guarantee that resources will be created in the correct subnet
		// The current solution is to allow only one subnet of type "cloud" and any subnet of type "vswitch" (technically limited to 1 though)
		// Official support for multiple "cloud" subnets can be added when using hcloud-go version >= 2.30.0
		// where ServerAttachToNetworkOpts allows to specify an "IPRange"
		// ref: https://pkg.go.dev/github.com/hetznercloud/hcloud-go/v2@v2.30.0/hcloud#ServerAttachToNetworkOpts

		// Create a new slice with only "cloud" typed subnet
		cloudSubnets := slices.Clone(networks[0].Subnets)
		cloudSubnets = slices.DeleteFunc(cloudSubnets, func(s hcloud.NetworkSubnet) bool {
			return s.Type == hcloud.NetworkSubnetTypeVSwitch
		})

		switch c := len(cloudSubnets); {
		case c > 1:
			return nil, fmt.Errorf("multiple subnet of type 'cloud' are currently not allowed")
		case c == 0:
			return nil, fmt.Errorf("a subnet of type 'cloud' is missing")
		case c == 1:
			configuredSubnet := s.scope.HetznerCluster.Spec.HCloudNetwork.SubnetCIDRBlock
			gotSubnet := cloudSubnets[0].IPRange.String()

			// Make sure the configured subnet CIDR matches the one available in the network
			if gotSubnet != configuredSubnet {
				return nil, fmt.Errorf("the subnet %s does not match the configured %s", gotSubnet, configuredSubnet)
			}
		}
	}

	return networks[0], nil
}

func statusFromHCloudNetwork(network *hcloud.Network) *infrav1.NetworkStatus {
	attachedServerIDs := make([]int64, 0, len(network.Servers))
	for _, s := range network.Servers {
		attachedServerIDs = append(attachedServerIDs, s.ID)
	}
	// The server IDs are not sorted by the API, but we want to have a
	// deterministic order to avoid unnecessary updates to the HetznerCluster resource.
	slices.Sort(attachedServerIDs)

	return &infrav1.NetworkStatus{
		ID:              network.ID,
		Labels:          network.Labels,
		AttachedServers: attachedServerIDs,
	}
}

func (s *Service) labels() map[string]string {
	clusterTagKey := s.scope.HetznerCluster.ClusterTagKey()
	return map[string]string{
		clusterTagKey: string(infrav1.ResourceLifecycleOwned),
	}
}
