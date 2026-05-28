import { describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";

import { TrivyKubeBenchProvider } from "../src/provider.js";
import { KUBE_BENCH_VERSION, TRIVY_VERSION } from "../src/tools-manifest.js";

const baseInput = (
  overrides: Partial<{ workdir: string; config: Record<string, unknown> }> = {},
) => {
  const wd = overrides.workdir ?? mkdtempSync(path.join(tmpdir(), "rt-test-"));
  return {
    runId: `rt-${Math.random().toString(36).slice(2, 10)}`,
    vibeId: "v1",
    workspaceId: "w1",
    repoUrl: "x",
    repoLocalPath: "/tmp",
    commit: "c",
    stage: "runtime.continuous" as const,
    profile: { kind: "backend", languages: ["ts"], runtimes: ["bun"] },
    policyLevel: "advisory" as const,
    config: overrides.config ?? {},
    workdir: wd,
  };
};

describe("TrivyKubeBenchProvider — identity + metadata", () => {
  test("provider name + stage are immutable identifiers", () => {
    const p = new TrivyKubeBenchProvider();
    expect(p.name).toBe("trivy-kube-bench");
    expect(p.stage).toBe("runtime.continuous");
  });

  test("toolVersion encodes both Trivy + kube-bench versions", () => {
    const p = new TrivyKubeBenchProvider();
    expect(p.toolVersion).toContain(TRIVY_VERSION);
    expect(p.toolVersion).toContain(KUBE_BENCH_VERSION);
  });

  test("metadata supports container + iac profiles", () => {
    const m = new TrivyKubeBenchProvider().metadata();
    expect(m.supportedProfiles).toContain("container");
    expect(m.supportedProfiles).toContain("iac");
    expect(m.stage).toBe("runtime.continuous");
  });

  test("cancel() on an unknown run is a no-op", async () => {
    const p = new TrivyKubeBenchProvider();
    await expect(p.cancel("nonexistent")).resolves.toBeUndefined();
  });
});

describe("TrivyKubeBenchProvider — graceful skips", () => {
  test("empty imageRefs emits trivy.no-images-configured info finding", async () => {
    const p = new TrivyKubeBenchProvider();
    // Pre-set state so run() doesn't try to ensureToolInstalled.
    (p as unknown as { trivyPath: string }).trivyPath = "/no/such/trivy";
    const result = await p.run(
      baseInput({
        config: {
          imageRefs: [],
          runKubeBench: false,
          skipKubeconfigProbe: true,
        },
      }),
    );
    expect(result.status).toBe("succeeded");
    const trivySkip = result.findings.find((f) => f.ruleId === "trivy.no-images-configured");
    expect(trivySkip).toBeDefined();
    expect(trivySkip?.severity).toBe("info");
    expect(trivySkip?.category).toBe("vuln");
  });

  test("runKubeBench=false emits kube-bench.skipped info finding", async () => {
    const p = new TrivyKubeBenchProvider();
    (p as unknown as { trivyPath: string }).trivyPath = "/no/such/trivy";
    const result = await p.run(baseInput({ config: { imageRefs: [], runKubeBench: false } }));
    expect(result.status).toBe("succeeded");
    const kbSkip = result.findings.find(
      (f) => f.ruleId === "kube-bench.skipped" && f.description?.includes("set to false"),
    );
    expect(kbSkip).toBeDefined();
    expect(kbSkip?.severity).toBe("info");
    expect(kbSkip?.category).toBe("config");
  });

  test("missing kubeconfig path emits kube-bench.skipped with missing-cluster-access reason", async () => {
    const p = new TrivyKubeBenchProvider();
    (p as unknown as { trivyPath: string }).trivyPath = "/no/such/trivy";
    (p as unknown as { kubeBenchAvailable: boolean }).kubeBenchAvailable = true;
    const result = await p.run(
      baseInput({
        config: {
          imageRefs: [],
          kubeconfigPath: "/nonexistent/kubeconfig-vibe-runtime-test",
          runKubeBench: true,
        },
      }),
    );
    expect(result.status).toBe("succeeded");
    const kbSkip = result.findings.find(
      (f) => f.ruleId === "kube-bench.skipped" && f.title.includes("missing-cluster-access"),
    );
    expect(kbSkip).toBeDefined();
  });

  test("docker unavailable but kubeconfig present → kube-bench.skipped docker-unavailable", async () => {
    const p = new TrivyKubeBenchProvider();
    (p as unknown as { trivyPath: string }).trivyPath = "/no/such/trivy";
    (p as unknown as { kubeBenchAvailable: boolean }).kubeBenchAvailable = false;
    const tmpKubeconfig = path.join(mkdtempSync(path.join(tmpdir(), "kc-")), "config");
    writeFileSync(tmpKubeconfig, "apiVersion: v1\nkind: Config\n", { mode: 0o600 });
    const result = await p.run(
      baseInput({
        config: {
          imageRefs: [],
          kubeconfigPath: tmpKubeconfig,
          runKubeBench: true,
        },
      }),
    );
    expect(result.status).toBe("succeeded");
    const kbSkip = result.findings.find(
      (f) => f.ruleId === "kube-bench.skipped" && f.title.includes("docker-unavailable"),
    );
    expect(kbSkip).toBeDefined();
  });
});

describe("TrivyKubeBenchProvider — trivy fixture parse", () => {
  test("fake trivy binary emitting fixture JSON normalises into vuln findings", async () => {
    const p = new TrivyKubeBenchProvider();
    // Build a tiny shell-script "trivy" that writes a fixture to --output.
    const dir = mkdtempSync(path.join(tmpdir(), "fake-trivy-"));
    const fakeTrivy = path.join(dir, "trivy");
    const fixture = {
      Results: [
        {
          Target: "alpine:3.19",
          Vulnerabilities: [
            {
              VulnerabilityID: "CVE-2025-12345",
              Severity: "HIGH",
              PkgName: "openssl",
              InstalledVersion: "3.0.0",
              FixedVersion: "3.0.13",
              Title: "openssl: buffer overflow",
              Description: "A buffer overflow in openssl",
            },
            {
              VulnerabilityID: "CVE-2025-99999",
              Severity: "CRITICAL",
              PkgName: "zlib",
              InstalledVersion: "1.2.11",
              FixedVersion: "1.2.13",
              Title: "zlib: heap corruption",
              Description: "Heap corruption in zlib",
            },
          ],
        },
      ],
    };
    // Script grabs the value following --output and writes fixture there.
    const script = `#!/usr/bin/env bash
set -e
OUT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) OUT="$2"; shift 2;;
    *) shift;;
  esac
done
if [[ -n "$OUT" ]]; then
  cat > "$OUT" <<'JSON'
${JSON.stringify(fixture, null, 2)}
JSON
fi
exit 0
`;
    writeFileSync(fakeTrivy, script, { mode: 0o755 });
    chmodSync(fakeTrivy, 0o755);

    (p as unknown as { trivyPath: string }).trivyPath = fakeTrivy;
    (p as unknown as { kubeBenchAvailable: boolean }).kubeBenchAvailable = false;
    const workdir = mkdtempSync(path.join(tmpdir(), "wd-"));
    const result = await p.run(
      baseInput({
        workdir,
        config: {
          imageRefs: ["alpine:3.19"],
          runKubeBench: false,
        },
      }),
    );
    expect(result.status).toBe("succeeded");
    const vulnFindings = result.findings.filter((f) => f.category === "vuln" && f.cve);
    expect(vulnFindings.length).toBe(2);
    const cveIds = vulnFindings.map((f) => f.cve).sort();
    expect(cveIds).toEqual(["CVE-2025-12345", "CVE-2025-99999"]);
    const critical = vulnFindings.find((f) => f.cve === "CVE-2025-99999");
    expect(critical?.severity).toBe("critical");
    expect(critical?.fixedVersion).toBe("1.2.13");
    const high = vulnFindings.find((f) => f.cve === "CVE-2025-12345");
    expect(high?.severity).toBe("high");
    expect(high?.ruleId).toBe("trivy.CVE-2025-12345");
    expect(result.evidence.length).toBeGreaterThanOrEqual(1);
    expect(result.evidence[0]?.type).toBe("grype-json");
  });
});
