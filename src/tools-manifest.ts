/**
 * Trivy binary manifest for the runtime.continuous lifecycle stage.
 *
 * Versions pinned per CalVer release. The v0.56.0 git tag exists in the
 * upstream aquasecurity/trivy repo but has NO GitHub release attached
 * and therefore no binary release assets (`trivy_0.56.0_<platform>.tar.gz`)
 * and no `trivy_0.56.0_checksums.txt`. Upstream binaries are only
 * published for the most recent point releases (v0.69.3 / v0.70.0 at
 * the time of writing).
 *
 * Until v0.56.0 binaries are published upstream (or this manifest is
 * bumped to a version that has real release assets), the sha256
 * entries below remain placeholders. The tool-installer hash check
 * will reject the placeholders and the provider will fall back to
 * PATH-resolution against `trivy --version`. Operators must install
 * trivy via the official package repos or `brew install trivy` to
 * unblock the runtime.continuous flow.
 *
 * TODO: backfill real sha256 values from
 *   https://github.com/aquasecurity/trivy/releases/download/v<VER>/trivy_<VER>_checksums.txt
 * once v0.56.0 publishes binary assets, or bump TRIVY_VERSION to a
 * release that does (e.g. v0.69.3) and pin its checksums.
 *
 * kube-bench is invoked from a known image at runtime (via kubectl run)
 * rather than as a host binary — we still pin the expected version in
 * `KUBE_BENCH_VERSION` so audit logs carry a stable identifier.
 */
import type { ToolManifest } from "@vibecontrols/vibe-plugin-security/tool-installer";

export const TRIVY_VERSION = "0.56.0";
export const KUBE_BENCH_VERSION = "0.7.4";
// Placeholder sha256: trivy v0.56.0 has no binary release assets
// upstream. Keep the version pin per the security plugin release spec
// and the tool-installer will fall back to PATH probe.
const TRIVY_TBD_SHA256 = "0000000000000000000000000000000000000000000000000000000000000000";

export const TOOLS_MANIFEST: ToolManifest = {
  trivy: {
    version: TRIVY_VERSION,
    binaryName: "trivy",
    versionMatcher: TRIVY_VERSION.replace(/\./g, "\\."),
    downloads: {
      "linux-x64": {
        url: `https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz`,
        sha256: TRIVY_TBD_SHA256,
        binaryWithinArchive: "trivy",
        archive: "tar.gz",
      },
      "linux-arm64": {
        url: `https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-ARM64.tar.gz`,
        sha256: TRIVY_TBD_SHA256,
        binaryWithinArchive: "trivy",
        archive: "tar.gz",
      },
      "darwin-x64": {
        url: `https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_macOS-64bit.tar.gz`,
        sha256: TRIVY_TBD_SHA256,
        binaryWithinArchive: "trivy",
        archive: "tar.gz",
      },
      "darwin-arm64": {
        url: `https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_macOS-ARM64.tar.gz`,
        sha256: TRIVY_TBD_SHA256,
        binaryWithinArchive: "trivy",
        archive: "tar.gz",
      },
    },
  },
};
