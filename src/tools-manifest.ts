/**
 * Trivy binary manifest for the runtime.continuous lifecycle stage.
 *
 * Pinned to v0.70.0 — the original pin v0.56.0 had a git tag in upstream
 * aquasecurity/trivy but NO GitHub release attached (no binary assets,
 * no checksums.txt). Repinned 2026-05-28 to v0.70.0 which ships full
 * binary releases for all 4 supported host platforms.
 *
 * kube-bench is invoked from a known image at runtime (via `kubectl run`)
 * rather than as a host binary — we still pin the expected version in
 * `KUBE_BENCH_VERSION` so audit logs carry a stable identifier.
 */
import type { ToolManifest } from "@vibecontrols/vibe-plugin-security/tool-installer";

export const TRIVY_VERSION = "0.70.0";
export const KUBE_BENCH_VERSION = "0.7.4";

export const TOOLS_MANIFEST: ToolManifest = {
  trivy: {
    version: TRIVY_VERSION,
    binaryName: "trivy",
    versionMatcher: TRIVY_VERSION.replace(/\./g, "\\."),
    downloads: {
      "linux-x64": {
        url: `https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz`,
        sha256: "8b4376d5d6befe5c24d503f10ff136d9e0c49f9127a4279fd110b727929a5aa9",
        binaryWithinArchive: "trivy",
        archive: "tar.gz",
      },
      "linux-arm64": {
        url: `https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-ARM64.tar.gz`,
        sha256: "2f6bb988b553a1bbac6bdd1ce890f5e412439564e17522b88a4541b4f364fc8d",
        binaryWithinArchive: "trivy",
        archive: "tar.gz",
      },
      "darwin-x64": {
        url: `https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_macOS-64bit.tar.gz`,
        sha256: "52d531452b19e7593da29366007d02a810e1e0080d02f9cf6a1afb46c35aaa93",
        binaryWithinArchive: "trivy",
        archive: "tar.gz",
      },
      "darwin-arm64": {
        url: `https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_macOS-ARM64.tar.gz`,
        sha256: "68e543c51dcc96e1c344053a4fde9660cf602c25565d9f09dc17dd41e13b838a",
        binaryWithinArchive: "trivy",
        archive: "tar.gz",
      },
    },
  },
};
