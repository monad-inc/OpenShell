<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Monad OpenShell build

This fork carries Monad's changes on top of upstream OpenShell releases: OCSF Authentication and Entity Management events, gateway control-plane audit, OTLP/gRPC log export, and raw OCSF push from the supervisor.

## Branches

| Branch | Purpose |
|---|---|
| `monad/main` | Trunk. Every push builds and publishes images. |
| `main` | Mirror of upstream `main`. Sync it through a PR; never commit Monad changes here. |
| `experiments/*` | Deployment experiments that track `monad/main`. |

## Images

`.github/workflows/monad-images.yml` builds the gateway, supervisor, and sandbox runtime for amd64 and arm64 and pushes them to `ghcr.io/monad-inc/openshell/{gateway,supervisor,sandbox}`. The packages are private.

| Tag | Meaning |
|---|---|
| `sha-<12 chars>` | Immutable build of one commit. Pin deployments to this or a version. |
| `<version>` | For example `0.1.3-pre.2.monad.14`: upstream base release plus the build number. |
| `main` | Latest build of `monad/main`. |
| `latest` | Latest `monad-v*` release tag. |

The gateway binary is compiled to launch Monad's supervisor and sandbox runtime images at the same `sha-` tag, so the gateway and supervisor always match.

Binaries build on the standard `ubuntu-24.04` and `ubuntu-24.04-arm` runners. To use larger org runners, set the repository variables `MONAD_RUNNER_X64` and `MONAD_RUNNER_ARM64` (for example `ubuntu-24.04-8core` and `ubuntu-24.04-arm-8core`); the runner group must allow this repository.

To cut a release, tag `monad/main` with `monad-v<semver>`, for example `git tag monad-v0.1.3-monad.1 && git push origin monad-v0.1.3-monad.1`.

## Pulling the images

Log in with a GitHub token that has `read:packages`:

```shell
echo "$GITHUB_TOKEN" | docker login ghcr.io -u <github-user> --password-stdin
docker pull ghcr.io/monad-inc/openshell/gateway:main
```

For Kubernetes, create a pull secret in the gateway namespace and in every sandbox namespace, then point the Helm chart at the Monad registry:

```shell
kubectl -n openshell create secret docker-registry ghcr-monad \
  --docker-server=ghcr.io --docker-username=<github-user> --docker-password="$GITHUB_TOKEN"
```

```yaml
global:
  image:
    registry: ghcr.io/monad-inc
    tag: sha-<12 chars>  # pin; `main` moves and IfNotPresent nodes won't re-pull it
imagePullSecrets:          # gateway pods
  - name: ghcr-monad
server:
  sandboxImagePullSecrets: # sandbox pods (supervisor + sandbox runtime)
    - name: ghcr-monad
```

## Moving to a new upstream release

1. Sync the fork's `main` from upstream through a PR.
2. Rebase `monad/main` onto the new release tag and run `mise run ci`.
3. Push `monad/main`; images build automatically.

Upstream's own workflows are disabled on this fork because they need NVIDIA's runners and secrets.
