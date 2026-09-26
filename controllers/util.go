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
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"
	conditions "sigs.k8s.io/cluster-api/util/conditions"
	deprecatedv1beta1conditions "sigs.k8s.io/cluster-api/util/conditions/deprecated/v1beta1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	infrav2 "github.com/syself/cluster-api-provider-hetzner/api/v1beta2"
	secretutil "github.com/syself/cluster-api-provider-hetzner/pkg/secrets"
	hcloudclient "github.com/syself/cluster-api-provider-hetzner/pkg/services/hcloud/client"
)

// This file holds the condition and token helpers for the controllers. util_v1beta1.go holds the
// counterparts for the controllers that have not been migrated yet, and can be deleted once they
// are.

// conditionsObject is an API object that owns both the conditions and the deprecated v1beta1
// conditions and can be status-patched. reconcileRateLimit and hcloudTokenErrorResult accept it so
// every controller that reconciles such an object shares them.
type conditionsObject interface {
	client.Object
	conditions.Setter
	deprecatedv1beta1conditions.Setter
}

// reconcileRateLimit checks whether the rate limit has been reached and returns whether the
// controller should wait a bit more. When the wait is over it clears the rate-limit conditions
// (HetznerAPIReachable marked reachable again, HCloudRateLimitExceeded deleted, since we cannot know
// the limit is gone until the next API call).
func reconcileRateLimit(obj conditionsObject, rateLimitWaitTime time.Duration) bool {
	condition := conditions.Get(obj, infrav2.HCloudRateLimitExceededCondition)
	if condition != nil && condition.Status == metav1.ConditionTrue {
		if time.Now().Before(condition.LastTransitionTime.Add(rateLimitWaitTime)) {
			// Rate limit wait has not elapsed yet, so signal the caller to requeue.
			// The caller requeues after a fixed interval rather than the exact remaining
			// wait, so that objects rate-limited together do not all reconcile at once.
			return true
		}
		// Wait time is over, we continue.
		deprecatedv1beta1conditions.MarkTrue(obj, infrav2.HetznerAPIReachableV1Beta1Condition)
		conditions.Delete(obj, infrav2.HCloudRateLimitExceededCondition)
	}

	return false
}

// getAndValidateHCloudToken acquires the Hetzner secret referenced by the cluster and returns the
// HCloud token and the options for the HCloud client from it (see hcloudClientOptions). It returns a
// *ResolveSecretRefError if the secret is missing, a *HCloudTokenValidationError if the token is
// empty and a *HCloudEndpointValidationError if the endpoint or the CA bundle is invalid, which the
// hcloudTokenErrorResult helpers map to the right conditions.
func getAndValidateHCloudToken(ctx context.Context, namespace string, hetznerCluster *infrav2.HetznerCluster, secretManager *secretutil.SecretManager) (string, []hcloudclient.ClientOption, *corev1.Secret, error) {
	// retrieve Hetzner secret
	secretNamespacedName := types.NamespacedName{Namespace: namespace, Name: hetznerCluster.Spec.HetznerSecret.Name}

	hetznerSecret, err := secretManager.AcquireSecret(
		ctx,
		secretNamespacedName,
		hetznerCluster,
		false,
		hetznerCluster.DeletionTimestamp.IsZero(),
	)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return "", nil, nil, &secretutil.ResolveSecretRefError{Message: fmt.Sprintf("The Hetzner secret %s does not exist", secretNamespacedName)}
		}
		return "", nil, nil, err
	}

	hcloudToken := string(hetznerSecret.Data[hetznerCluster.Spec.HetznerSecret.Key.HCloudToken])

	// Validate token
	if hcloudToken == "" {
		return "", nil, nil, &secretutil.HCloudTokenValidationError{}
	}

	key := hetznerCluster.Spec.HetznerSecret.Key
	clientOpts, err := hcloudClientOptions(hetznerSecret, key.HCloudEndpoint, key.HCloudCABundle)
	if err != nil {
		return "", nil, nil, err
	}

	return hcloudToken, clientOpts, hetznerSecret, nil
}

// The keys of the Hetzner secret that hold the HCloud API endpoint and the CA bundle for it, when
// spec.hetznerSecretRef.key does not name them. They match the CRD defaults, and they also apply
// when the installed CRDs predate these fields.
const (
	defaultHCloudEndpointKey = "hcloud-endpoint"
	defaultHCloudCABundleKey = "hcloud-ca-bundle"
)

// hcloudClientOptions returns the options for an HCloud client from the optional endpoint and CA
// bundle keys of the Hetzner secret, so that each cluster can use its own HCloud API. Missing or
// empty keys add no option: the client then uses HCLOUD_ENDPOINT or the default endpoint, and the
// system roots. It returns a *HCloudEndpointValidationError if a value is invalid.
func hcloudClientOptions(hetznerSecret *corev1.Secret, endpointKey, caBundleKey string) ([]hcloudclient.ClientOption, error) {
	if endpointKey == "" {
		endpointKey = defaultHCloudEndpointKey
	}
	if caBundleKey == "" {
		caBundleKey = defaultHCloudCABundleKey
	}

	var opts []hcloudclient.ClientOption

	if endpoint := string(hetznerSecret.Data[endpointKey]); endpoint != "" {
		if err := hcloudclient.ValidateEndpoint(endpoint); err != nil {
			return nil, &secretutil.HCloudEndpointValidationError{Message: fmt.Sprintf("key %q: %s", endpointKey, err)}
		}
		opts = append(opts, hcloudclient.WithEndpoint(endpoint))
	}

	if caBundle := hetznerSecret.Data[caBundleKey]; len(caBundle) > 0 {
		if _, err := hcloudclient.ParseCABundle(caBundle); err != nil {
			return nil, &secretutil.HCloudEndpointValidationError{Message: fmt.Sprintf("key %q: %s", caBundleKey, err)}
		}
		opts = append(opts, hcloudclient.WithCABundle(caBundle))
	}

	return opts, nil
}

// hcloudTokenErrorResult handles errors from getAndValidateHCloudToken. It sets the
// HCloudTokenAvailable condition, computes the Ready summary, and writes the status once.
func hcloudTokenErrorResult(
	ctx context.Context,
	inerr error,
	obj conditionsObject,
	crClient client.Client,
	summaryOpts []conditions.SummaryOption,
) (ctrl.Result, error) {
	res := ctrl.Result{}

	switch inerr.(type) {
	// In the event that the reference to the secret is defined, but we cannot find it
	// we requeue the host as we will not know if they create the secret
	// at some point in the future.
	case *secretutil.ResolveSecretRefError:
		deprecatedv1beta1conditions.MarkFalse(obj,
			infrav2.HCloudTokenAvailableV1Beta1Condition,
			infrav2.HetznerSecretUnreachableV1Beta1Reason,
			clusterv1.ConditionSeverityError,
			"could not find HetznerSecret",
		)
		conditions.Set(obj, metav1.Condition{
			Type:    infrav2.HCloudTokenAvailableCondition,
			Status:  metav1.ConditionFalse,
			Reason:  infrav2.HCloudTokenSecretUnreachableReason,
			Message: "could not find HetznerSecret",
		})
		res = ctrl.Result{RequeueAfter: secretErrorRetryDelay}
		inerr = nil

	// No need to reconcile again, as it will be triggered as soon as the secret is updated.
	case *secretutil.HCloudTokenValidationError:
		deprecatedv1beta1conditions.MarkFalse(obj,
			infrav2.HCloudTokenAvailableV1Beta1Condition,
			infrav2.HCloudCredentialsInvalidV1Beta1Reason,
			clusterv1.ConditionSeverityError,
			"invalid or not specified hcloud token in Hetzner secret",
		)
		conditions.Set(obj, metav1.Condition{
			Type:    infrav2.HCloudTokenAvailableCondition,
			Status:  metav1.ConditionFalse,
			Reason:  infrav2.HCloudTokenInvalidReason,
			Message: "invalid or not specified hcloud token in Hetzner secret",
		})

	// Handled like an invalid token.
	case *secretutil.HCloudEndpointValidationError:
		deprecatedv1beta1conditions.MarkFalse(obj,
			infrav2.HCloudTokenAvailableV1Beta1Condition,
			infrav2.HCloudCredentialsInvalidV1Beta1Reason,
			clusterv1.ConditionSeverityError,
			"%s",
			inerr.Error(),
		)
		conditions.Set(obj, metav1.Condition{
			Type:    infrav2.HCloudTokenAvailableCondition,
			Status:  metav1.ConditionFalse,
			Reason:  infrav2.HCloudTokenInvalidReason,
			Message: inerr.Error(),
		})

	default:
		deprecatedv1beta1conditions.MarkFalse(obj,
			infrav2.HCloudTokenAvailableV1Beta1Condition,
			infrav2.HCloudCredentialsInvalidV1Beta1Reason,
			clusterv1.ConditionSeverityError,
			"%s",
			inerr.Error(),
		)
		conditions.Set(obj, metav1.Condition{
			Type:    infrav2.HCloudTokenAvailableCondition,
			Status:  metav1.ConditionFalse,
			Reason:  infrav2.HCloudTokenInvalidReason,
			Message: inerr.Error(),
		})
		return reconcile.Result{}, fmt.Errorf("an unhandled failure occurred with the Hetzner secret: %w", inerr)
	}

	deprecatedv1beta1conditions.SetSummary(obj)

	if len(summaryOpts) > 0 {
		if readyCondition, err := conditions.NewSummaryCondition(
			obj,
			clusterv1.ReadyCondition,
			summaryOpts...,
		); err == nil {
			conditions.Set(obj, *readyCondition)
		}
	}

	if err := crClient.Status().Update(ctx, obj); err != nil {
		return reconcile.Result{}, fmt.Errorf("hcloudTokenErrorResult: failed to update: %w", err)
	}
	if inerr != nil {
		return reconcile.Result{}, inerr
	}
	return res, nil
}
