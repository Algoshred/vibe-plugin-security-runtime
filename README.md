## @vibecontrols/vibe-plugin-security-runtime

Continuous runtime-check provider for the `runtime.continuous` lifecycle stage in [VibeControls](https://vibecontrols.com). Provider name: `trivy-kube-bench`. Wraps the pinned `trivy` binary and the `kube-bench` cluster check. **Wave 2 scaffold — real tool integration pending; see `src/provider.ts` TODO.**

Registers itself with [`@vibecontrols/vibe-plugin-security`](https://www.npmjs.com/package/@vibecontrols/vibe-plugin-security) under the per-stage provider type `security.runtime` (per `PROVIDER_TYPE_FOR_STAGE("runtime.continuous")`). When the user picks "trivy-kube-bench" as their default provider for `runtime.continuous`, the security meta plugin dispatches scan runs here.

## Install

```bash
vibe plugin install @vibecontrols/vibe-plugin-security-runtime
vibe security providers set-default --stage runtime.continuous --provider trivy-kube-bench
```

On first real run the plugin downloads the Trivy binary (sha256-verified per platform) into `~/.boff/vibecontrols/agents/<profile>/tools/trivy/`. `kube-bench` is invoked via `kubectl run` from a pinned image.

## Behavior (planned)

- Rescans every image listed in `input.config.images` (or auto-discovered from the cluster) with Trivy (`--format sarif`), normalizing SARIF into `category: "vuln"` findings.
- Runs kube-bench against the cluster control-plane / nodes (`--json`), normalizing the result into `category: "config"` findings.
- **Skip path**: when no kubeconfig is present, the kubeconfig file is missing, or `kubectl get nodes` fails, the provider returns `succeeded` with a single info finding describing the skip reason (`missing-cluster-access`). The dispatcher records `conclusion: skipped`.

## Configuration

Per-vibe config (stored in `RepositorySecurityConfig.pluginAssignments["runtime.continuous"].config`):

```yaml
provider: trivy-kube-bench
config:
  images:
    - registry.example.com/app:1.2.3
  kubeconfig: /etc/vibe/kubeconfig # optional override
  registryAuth:
    server: registry.example.com
    username: vibe-readonly
    password: "<secret>"
  extraTrivyArgs: []
  extraKubeBenchArgs: []
```

## License

Proprietary — Burdenoff Consultancy Services Pvt. Ltd.
