#!/usr/bin/env bash
# Lint + render the Paddock chart in its main configurations and (if
# kubeconform is on PATH) validate every manifest against the Kubernetes
# OpenAPI schemas. Used by CI (.github/workflows/ci.yml, job "helm") and
# runnable locally:  bash deploy/helm/ci-check.sh
set -euo pipefail
HELM=${HELM:-helm}
KUBECONFORM=${KUBECONFORM:-kubeconform}
KUBE_VERSION=${KUBE_VERSION:-1.30.0}
CHART=$(cd "$(dirname "$0")/paddock" && pwd)
OUT=${OUT:-$(mktemp -d)}
mkdir -p "$OUT"

ext=(--set secrets.databaseUrl=postgresql://paddock:pw@db.example:5432/asm
     --set secrets.redisUrl=redis://redis.example:6379/0)

declare -A profiles=(
  [default]="${ext[*]}"
  [bundled]="--set postgresql.enabled=true --set redis.enabled=true"
  [existing-secret]="--set secrets.existingSecret=paddock-prod --set otdiscovery.ingress.enabled=true --set metrics.serviceMonitor.enabled=true --set metrics.prometheusRule.enabled=true --set workerActive.screenshots.persistence=true"
  [minimal]="${ext[*]} --set networkPolicy.enabled=false --set ingress.enabled=false --set orchestrator.autoscaling.enabled=false --set dashboard.enabled=false --set integrationsWorker.enabled=false --set migrations.enabled=false"
)

for name in "${!profiles[@]}"; do
  # shellcheck disable=SC2086
  read -r -a args <<<"${profiles[$name]}"
  echo "==> helm lint ($name)"
  "$HELM" lint "$CHART" "${args[@]}" 2> >(grep -v 'found symbolic link' >&2)
  echo "==> helm template ($name)"
  "$HELM" template paddock "$CHART" --namespace paddock --kube-version "$KUBE_VERSION" \
    "${args[@]}" 2> >(grep -v 'found symbolic link' >&2) >"$OUT/$name.yaml"
  if command -v "$KUBECONFORM" >/dev/null; then
    echo "==> kubeconform ($name)"
    "$KUBECONFORM" -strict -summary -kubernetes-version "$KUBE_VERSION" \
      -ignore-missing-schemas "$OUT/$name.yaml"
  fi
done

# Hardening invariants every rendered workload must satisfy.
python3 - "$OUT" <<'PY'
import glob, sys, yaml
bad = []
for path in glob.glob(sys.argv[1] + "/*.yaml"):
    for doc in yaml.safe_load_all(open(path)):
        if not doc or doc.get("kind") not in ("Deployment", "StatefulSet", "Job"):
            continue
        spec = doc["spec"]["template"]["spec"]
        name = f'{path.rsplit("/", 1)[-1]}:{doc["kind"]}/{doc["metadata"]["name"]}'
        if not spec.get("securityContext", {}).get("runAsNonRoot"):
            bad.append(f"{name}: runAsNonRoot")
        for c in spec.get("containers", []) + spec.get("initContainers", []):
            sc = c.get("securityContext", {})
            caps = sc.get("capabilities", {})
            if sc.get("allowPrivilegeEscalation") is not False:
                bad.append(f"{name}/{c['name']}: allowPrivilegeEscalation")
            if sc.get("readOnlyRootFilesystem") is not True:
                bad.append(f"{name}/{c['name']}: readOnlyRootFilesystem")
            if caps.get("drop") != ["ALL"]:
                bad.append(f"{name}/{c['name']}: capabilities.drop != [ALL]")
            added = caps.get("add") or []
            if added and not (added == ["NET_RAW"] and "worker-active" in doc["metadata"]["name"]):
                bad.append(f"{name}/{c['name']}: unexpected capabilities.add {added}")
            if "resources" not in c:
                bad.append(f"{name}/{c['name']}: resources")
if bad:
    print("hardening invariants FAILED:\n  " + "\n  ".join(bad))
    sys.exit(1)
print("hardening invariants OK")
PY
echo "rendered manifests in $OUT"
