# Changes in This Fork Compared to Upstream

This repository is a fork of [syself/cluster-api-provider-hetzner](https://github.com/syself/cluster-api-provider-hetzner). It adds one capability that upstream does not have: CAPH can talk to an HCloud API other than `https://api.hetzner.cloud/v1`, for example an API emulator, a test double or a private cloud that implements the HCloud API.

The capability comes as two changes. Everything else is unchanged upstream code.

| #   | Change                                                                                                    | Scope                | Commit on `main` line | Commit on `v1.1.8` line |
| --- | --------------------------------------------------------------------------------------------------------- | -------------------- | --------------------- | ----------------------- |
| 1   | [HCloud API endpoint from `HCLOUD_ENDPOINT`](#1-hcloud-api-endpoint-from-hcloud_endpoint)                 | Whole controller     | `8430aa15`            | `a338fa59`              |
| 2   | [HCloud API endpoint and CA bundle per cluster](#2-hcloud-api-endpoint-and-ca-bundle-per-cluster)         | One `HetznerCluster` | `a8c73c3a`            | `324a10f5`              |

State of this document: 2026-10-02, upstream `main` at `78c27f0f`, upstream release `v1.1.8`. Neither change has been submitted to upstream so far.

## Branches

The changes belong together and live in one branch, `hcloud-endpoint-secret`: both code changes and this documentation, on top of upstream `main`.

| Branch                   | Based on          | Contains                         | API versions with the new fields |
| ------------------------ | ----------------- | -------------------------------- | -------------------------------- |
| `hcloud-endpoint-secret` | upstream `main`   | changes 1, 2, this documentation | `v1beta1`, `v1beta2`             |
| `v1.1.8-paasbox`         | upstream `v1.1.8` | changes 1, 2                     | `v1beta1`                        |
| `hcloud-endpoint`        | upstream `main`   | change 1                         | –                                |
| `main`                   | upstream `main`   | no changes                       | –                                |

`v1.1.8-paasbox` is the backport to the released version `v1.1.8`, which only has the `v1beta1` API. Its head is tagged `v1.1.8-paasbox.2`. `hcloud-endpoint` is the first commit of `hcloud-endpoint-secret` on its own. `main` mirrors upstream `main` and carries no fork changes. No container image of the fork is published: build it from the branch you need.

To list the fork's commits yourself:

```shell
git fetch upstream
git log --oneline upstream/main..hcloud-endpoint-secret
git log --oneline v1.1.8..v1.1.8-paasbox
```

## 1. HCloud API endpoint from `HCLOUD_ENDPOINT`

**Upstream:** CAPH always calls `https://api.hetzner.cloud/v1`. It builds the hcloud-go client without an endpoint, and hcloud-go reads no environment variable. Running CAPH against another HCloud API needs a DNS and TLS redirect of `api.hetzner.cloud`.

**This fork:** if the environment variable `HCLOUD_ENDPOINT` is set on the `manager` container of the `caph-controller-manager` Deployment, every HCloud client of the controller uses it. Leading and trailing whitespace is ignored. If the variable is unset or empty, nothing changes. The hcloud CLI and the hcloud cloud controller manager read the same variable.

```shell
kubectl -n caph-system set env deployment/caph-controller-manager -c manager \
  HCLOUD_ENDPOINT=https://hcloud.example.com/v1
```

Notes:

- The value applies to all clusters that this CAPH manages. Use change 2 to set it per cluster.
- The value of the variable is not validated. A wrong value shows up as failing HCloud API calls.
- If the endpoint's certificate is issued by a private CA, either use the CA bundle of change 2, or set `SSL_CERT_FILE` to the path of the CA's PEM file in the container. `SSL_CERT_FILE` replaces the system roots of the whole process.

Code: `pkg/services/hcloud/client/client.go` (`EndpointEnvVar`, `NewClient`).

## 2. HCloud API endpoint and CA bundle per cluster

**Upstream:** no per-cluster setting exists.

**This fork:** the Hetzner secret that `spec.hetznerSecretRef` of a `HetznerCluster` names takes two more keys. Both are optional.

| Key in the secret  | Content                                                              | If missing or empty                                     |
| ------------------ | -------------------------------------------------------------------- | ------------------------------------------------------- |
| `hcloud-endpoint`  | Endpoint of the HCloud API for this cluster                          | `HCLOUD_ENDPOINT`, then `https://api.hetzner.cloud/v1` |
| `hcloud-ca-bundle` | PEM-encoded CA certificates that this cluster's HCloud client trusts | Only the system roots are trusted                       |

```shell
kubectl create secret generic hetzner --from-literal=hcloud=$HCLOUD_TOKEN \
  --from-literal=hcloud-endpoint=https://hcloud.example.com/v1 \
  --from-file=hcloud-ca-bundle=ca.crt
```

With this, one CAPH can manage clusters on Hetzner and clusters on other endpoints side by side.

### Behavior

- **Order of precedence for the endpoint:** the key in the secret, then `HCLOUD_ENDPOINT`, then `https://api.hetzner.cloud/v1`.
- **CA bundle:** the certificates are trusted in addition to the system roots, and only by the HCloud client of the cluster whose secret holds them. The two keys are independent: a CA bundle also applies when the endpoint comes from `HCLOUD_ENDPOINT`.
- **Validation:** the endpoint must be an absolute `http` or `https` URL. The CA bundle must hold at least one PEM block, and every PEM block must be a certificate that parses. Text outside of PEM blocks is ignored.
- **Errors:** an invalid endpoint or CA bundle is handled like an invalid token. The condition `HCloudTokenAvailable` becomes `False` with the reason `Invalid` (`HCloudCredentialsInvalid` in the `v1beta1` conditions), and the message names the key and the cause.
- **Workload cluster:** neither key is copied to the Hetzner secret in the workload cluster. Components there, such as the cloud controller manager, need their own endpoint configuration.
- **Hetzner Robot:** the Robot client for bare metal servers is not affected.
- **Controllers that use the settings:** HetznerCluster, HCloudMachine, HCloudMachineTemplate, HCloudRemediation and HetznerBareMetalMachine.

### API changes

`HetznerCluster` and `HetznerClusterTemplate` get two optional fields that set the names of the keys, like the existing fields for the token and the Robot credentials:

| Field                                      | Default            |
| ------------------------------------------ | ------------------ |
| `spec.hetznerSecretRef.key.hcloudEndpoint` | `hcloud-endpoint`  |
| `spec.hetznerSecretRef.key.hcloudCABundle` | `hcloud-ca-bundle` |

The controller falls back to the default names when the fields are empty. The two keys of the secret therefore also work when the installed CRDs predate the fields.

### Code changes

- `pkg/services/hcloud/client`: `Factory.NewClient` takes functional options (`WithEndpoint`, `WithCABundle`). Calls of the form `NewClient(token)` are unchanged. `ValidateEndpoint` and `ParseCABundle` check the values.
- Clients are still created per reconcile. The transport for a CA bundle is cached by the SHA-256 hash of the bundle, so that its connection pool survives.
- The logging transport (`DebugAPICalls`) wraps `http.DefaultTransport` when the client has no transport of its own, instead of `nil`.
- `pkg/secrets`: new error type `HCloudEndpointValidationError`.
- `controllers`: `getAndValidateHCloudToken` also returns the client options. The helpers are in `controllers/util.go` on `hcloud-endpoint-secret` and in `controllers/hetznercluster_controller.go` on `v1.1.8-paasbox`.
- `api/v1beta1` and `api/v1beta2` (`v1.1.8-paasbox`: `api/v1beta1` only): the two fields of `HetznerSecretKeyRef`, and the generated CRDs in `config/crd/bases`.
- The mock of the client factory is regenerated (`.mockery.yaml`).

## Changes to the upstream documentation

The fork also describes both changes in the regular documentation:

- [Preparation](/docs/caph/01-getting-started/03-preparation.md), section "Create a secret for hcloud only": how to set the endpoint and the CA bundle.
- [HetznerCluster reference](/docs/caph/03-reference/02-hetzner-cluster.md): the fields `hetznerSecret.key.hcloudEndpoint` and `hetznerSecret.key.hcloudCABundle`.
