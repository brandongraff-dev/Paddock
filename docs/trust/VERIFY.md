# Verifying a Paddock release

Every tagged release (`vX.Y.Z`) is built by `.github/workflows/release.yml` on
GitHub-hosted runners and published to GHCR as
`ghcr.io/<owner>/paddock-<service>`. For each image the workflow produces:

| Artifact | How it is made | Where it lives |
|---|---|---|
| Image signature | `cosign sign` **keyless** (GitHub OIDC → Sigstore Fulcio certificate, logged in Rekor) | registry (`.sig` tag) |
| SBOM — SPDX 2.3 JSON | `syft` (anchore/sbom-action) on the pushed digest | signed in-toto attestation in the registry + GitHub release asset |
| SBOM — CycloneDX JSON | `syft` | signed in-toto attestation + release asset |
| SLSA build provenance (v1) | `actions/attest-build-provenance` | registry + GitHub attestation store |
| `IMAGE_DIGESTS.txt`, `SBOM_SHA256SUMS.txt` | digest/sha256 manifests | release assets, each with a keyless `*.sigstore.json` bundle |
| `BUNDLE_SHA256SUMS.txt` | sha256 of the install zip and the stamped `install.ps1` / `install.sh` | release asset with a keyless `*.sigstore.json` bundle |

No long-lived signing key exists. Trust is rooted in the GitHub Actions OIDC
identity of the release workflow **at a tag ref** of this repository.

Set these once (replace `OWNER` with the GitHub org/user that publishes, e.g.
the repository owner):

```bash
OWNER=brandongraff-dev            # GitHub owner of the repo
REPO=$OWNER/cybersec
TAG=v1.2.3
SVC=orchestrator                  # any service: dashboard, worker-active, intel, ...
IMG=ghcr.io/$OWNER/paddock-$SVC
ID="https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$TAG"
ISSUER=https://token.actions.githubusercontent.com
```

Always verify and deploy **by digest**, not by tag:

```bash
DIGEST=$(crane digest "$IMG:${TAG#v}")    # or: docker buildx imagetools inspect
REF="$IMG@$DIGEST"
```

## 1. Signature (who built it)

```bash
cosign verify "$REF" \
  --certificate-identity "$ID" \
  --certificate-oidc-issuer "$ISSUER"
```

Pinning the identity to the tag ref rejects images signed by any other
workflow, branch, fork or repository.

## 2. SBOM attestations (what is inside)

```bash
cosign verify-attestation "$REF" --type spdxjson \
  --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER" \
  | jq -r '.payload' | base64 -d | jq '.predicate' > sbom.spdx.json

cosign verify-attestation "$REF" --type cyclonedx \
  --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER" \
  | jq -r '.payload' | base64 -d | jq '.predicate' > sbom.cdx.json

# scan it yourself
grype sbom:sbom.cdx.json
```

The same SBOM files are attached to the GitHub release; check them against the
signed manifest:

```bash
gh release download "$TAG" -R "$REPO" -p 'SBOM_SHA256SUMS.txt*' -p '*.json'
cosign verify-blob SBOM_SHA256SUMS.txt \
  --bundle SBOM_SHA256SUMS.txt.sigstore.json \
  --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER"
sha256sum -c SBOM_SHA256SUMS.txt
```

### The Windows setup app and install bundle

`Paddock-Setup.exe`, `paddock-lite-X.Y.Z.zip`, `install.ps1` and `install.sh` are
attached to each release. The exe is **not code-signed yet** (Windows SmartScreen
warns on first run); its integrity comes from the signed checksum file below and,
additionally, `gh attestation verify Paddock-Setup.exe -R "$REPO"` (SLSA build
provenance). Check them before running anything you downloaded:

```bash
gh release download "$TAG" -R "$REPO" -p 'BUNDLE_SHA256SUMS.txt*' -p 'Paddock-Setup.exe' -p 'paddock-lite-*.zip' -p 'install.*'
cosign verify-blob BUNDLE_SHA256SUMS.txt \
  --bundle BUNDLE_SHA256SUMS.txt.sigstore.json \
  --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER"
sha256sum -c BUNDLE_SHA256SUMS.txt
```

The installers only pull the images of the version they are stamped with, and
the images are signed as in section 1.

## 3. SLSA provenance (how and from what it was built)

```bash
gh attestation verify "oci://$REF" -R "$REPO" \
  --signer-workflow "$REPO/.github/workflows/release.yml"
```

or with cosign (the provenance is stored as an OCI referrer in the Sigstore
bundle format, which needs cosign >= 2.4 and `--new-bundle-format`):

```bash
cosign verify-attestation "$REF" --new-bundle-format --type slsaprovenance1 \
  --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER" \
  | jq -r '.payload' | base64 -d \
  | jq '.predicate.buildDefinition.resolvedDependencies'
```

The predicate names the source repository, the exact commit and the workflow
that built the image.

## 4. The release digest manifest

```bash
gh release download "$TAG" -R "$REPO" -p 'IMAGE_DIGESTS.txt*'
cosign verify-blob IMAGE_DIGESTS.txt \
  --bundle IMAGE_DIGESTS.txt.sigstore.json \
  --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER"
cat IMAGE_DIGESTS.txt     # "<digest>  <image>" for every service of the release
```

## 5. Enforce at deploy time

Kubernetes (Sigstore policy-controller / Kyverno) — admit only images signed by
the release workflow:

```yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata: { name: paddock-release }
spec:
  images: [{ glob: "ghcr.io/OWNER/paddock-*" }]
  authorities:
    - keyless:
        url: https://fulcio.sigstore.dev
        identities:
          - issuer: https://token.actions.githubusercontent.com
            subjectRegExp: "^https://github.com/OWNER/cybersec/.github/workflows/release.yml@refs/tags/v.*$"
```

docker-compose: pin every `image:` to `@sha256:<digest>` from the verified
`IMAGE_DIGESTS.txt` instead of building locally.

## Honest limits

* Third-party actions in the workflow are pinned to major-version tags, not
  commit SHAs; a compromised action tag could affect a build. Pin to SHAs
  before relying on this for regulated releases.
* Builds are not bit-for-bit **reproducible** yet (base images are tag-pinned,
  `apt`/`pip` resolve at build time). Provenance proves *where/how* an image
  was built, not that you can rebuild the identical bytes.
* The worker-active image is built for `linux/amd64` only.
* `docker-compose.yml` still builds images from source by default; the signed
  images only protect you if you deploy them by digest.
