/**
 * Trivy binary manifest for the runtime.continuous lifecycle stage.
 *
 * Versions pinned per CalVer release. sha256 values below are placeholders
 * (zeros) — TODO(wave-2): pin to upstream checksums sourced from
 *   https://github.com/aquasecurity/trivy/releases/download/v<VER>/trivy_<VER>_checksums.txt
 * before enabling real downloads in production.
 *
 * kube-bench is invoked from a known image at runtime (via kubectl run)
 * rather than as a host binary — we still pin the expected version in
 * `KUBE_BENCH_VERSION` so audit logs carry a stable identifier.
 *
 * Updating the version is a deliberate, audited operation.
 */
import type { ToolManifest } from "@vibecontrols/vibe-plugin-security/tool-installer";

export const TRIVY_VERSION = "0.56.0";
export const KUBE_BENCH_VERSION = "0.7.4";
const PLACEHOLDER_SHA256 = "0000000000000000000000000000000000000000000000000000000000000000";

export const TOOLS_MANIFEST: ToolManifest = {
  trivy: {
    version: TRIVY_VERSION,
    binaryName: "trivy",
    versionMatcher: TRIVY_VERSION.replace(/\./g, "\\."),
    downloads: {
      "linux-x64": {
        url: `https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz`,
        sha256: PLACEHOLDER_SHA256,
        binaryWithinArchive: "trivy",
        archive: "tar.gz",
      },
      "linux-arm64": {
        url: `https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-ARM64.tar.gz`,
        sha256: PLACEHOLDER_SHA256,
        binaryWithinArchive: "trivy",
        archive: "tar.gz",
      },
      "darwin-x64": {
        url: `https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_macOS-64bit.tar.gz`,
        sha256: PLACEHOLDER_SHA256,
        binaryWithinArchive: "trivy",
        archive: "tar.gz",
      },
      "darwin-arm64": {
        url: `https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_macOS-ARM64.tar.gz`,
        sha256: PLACEHOLDER_SHA256,
        binaryWithinArchive: "trivy",
        archive: "tar.gz",
      },
    },
  },
};
