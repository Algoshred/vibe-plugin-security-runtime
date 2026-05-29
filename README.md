<!-- VIBECONTROLS_OSS_HEADER_START -->

> **License**: MIT — see [LICENSE](./LICENSE).
> **Note**: This plugin is open source. The `@vibecontrols/agent` runtime that loads it is **not** open source — it is a proprietary product of Burdenoff Consultancy Services Pvt. Ltd. See [vibecontrols.com](https://vibecontrols.com) for the agent.

<!-- VIBECONTROLS_OSS_HEADER_END -->

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

<!-- VIBECONTROLS_OSS_FOOTER_START -->

---

## License

Released under the [MIT License](./LICENSE).

Copyright (c) 2026 Burdenoff Consultancy Services Private Limited, Algoshred Technologies Private Limited, and all its sister companies.

Maintainer: **Vignesh T.V** — <https://github.com/tvvignesh>

## Credits

This plugin builds on the following upstream open-source projects. All trademarks and copyrights remain with their respective owners.

- **Trivy** — <https://github.com/aquasecurity/trivy>
- **kube-bench** — <https://github.com/aquasecurity/kube-bench>

## About VibeControls

**VibeControls** is the agentic engineering mission control for AI-native teams. Vibe-plugins extend the VibeControls agent with new providers, tools, sessions, tunnels, storage backends, and security stages.

- Website: <https://vibecontrols.com>
- Documentation: <https://docs.vibecontrols.com>
- Plugin SDK: <https://github.com/algoshred/vibecontrols-plugin-sdk>
- All plugins: <https://github.com/algoshred?q=vibe-plugin-&type=all>

## Important: agent is not open source

The `@vibecontrols/agent` runtime that loads and orchestrates these plugins is **closed source** and proprietary to Burdenoff Consultancy Services Pvt. Ltd. Only the plugin contract and the plugins themselves are released under MIT. If you want a fully self-hostable agent, please open an issue or contact the maintainer.

<!-- VIBECONTROLS_OSS_FOOTER_END -->
