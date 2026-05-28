import { describe, expect, test } from "bun:test";

import { TrivyKubeBenchProvider } from "../src/provider.js";
import { KUBE_BENCH_VERSION, TRIVY_VERSION } from "../src/tools-manifest.js";

const baseInput = (config: Record<string, unknown> = {}) => ({
  runId: "rt-1",
  vibeId: "v1",
  workspaceId: "w1",
  repoUrl: "x",
  repoLocalPath: "/tmp",
  commit: "c",
  stage: "runtime.continuous" as const,
  profile: { kind: "backend", languages: ["ts"], runtimes: ["bun"] },
  policyLevel: "advisory" as const,
  config,
  workdir: "/tmp",
});

describe("TrivyKubeBenchProvider", () => {
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

  test("run() with explicit non-existent kubeconfig hits the skip path", async () => {
    const p = new TrivyKubeBenchProvider();
    const result = await p.run(
      baseInput({
        // Point at a path that cannot exist — fast deterministic skip.
        skipKubeconfigProbe: false,
        kubeconfig: "/nonexistent/kubeconfig-vibe-runtime-test",
        images: ["registry.example.com/app:1.0.0"],
      }),
    );
    expect(result.status).toBe("succeeded");
    expect(result.findings.length).toBe(1);
    expect(result.findings[0].severity).toBe("info");
    expect(result.findings[0].category).toBe("config");
    expect(result.findings[0].ruleId).toBe("trivy-kube-bench.skipped");
    expect(result.findings[0].description).toMatch(/missing-cluster-access/);
  });

  test("run() with skipKubeconfigProbe emits stub finding (real impl pending)", async () => {
    const p = new TrivyKubeBenchProvider();
    const result = await p.run(
      baseInput({
        skipKubeconfigProbe: true,
        images: ["registry.example.com/app:1.0.0"],
      }),
    );
    expect(result.status).toBe("succeeded");
    expect(result.findings.length).toBe(1);
    expect(result.findings[0].ruleId).toBe("trivy-kube-bench.stub");
  });

  test("cancel() on an unknown run is a no-op", async () => {
    const p = new TrivyKubeBenchProvider();
    await expect(p.cancel("nonexistent")).resolves.toBeUndefined();
  });
});
