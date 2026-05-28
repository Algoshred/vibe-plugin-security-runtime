/**
 * TrivyKubeBenchProvider — implements SecurityProvider for stage
 * `runtime.continuous`.
 *
 * Wave 2 scaffold. The real implementation will:
 *  - Resolve a pinned Trivy binary via TOOLS_MANIFEST + tool-installer.
 *  - For each image in `input.config.images` (or auto-discovered from
 *    the cluster), run `trivy image --format sarif --output <workdir>/trivy-<image>.sarif <image>`
 *    and normalize the SARIF via normalizeSarif() with category "vuln".
 *  - Probe kubeconfig (`~/.kube/config` or `$KUBECONFIG`) reachability:
 *      * If missing or `kubectl get nodes` fails → return `succeeded`
 *        with `conclusion: skipped` + a single info finding describing
 *        the skip reason.
 *  - Run kube-bench against the cluster control-plane / nodes via
 *    `kube-bench --json --outputfile <workdir>/kube-bench.json` and
 *    normalize the result into NormalizedFindings (category "config").
 *
 * Today this stub records that the stage ran (or was skipped) so the
 * dispatcher can chain the next stage. The skip path is fully wired.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import * as path from "node:path";

import type { HostServices } from "@vibecontrols/plugin-sdk/contract";
import { resolveToolPath } from "@vibecontrols/vibe-plugin-security/tool-installer";
import type {
  NormalizedFinding,
  ScanEvidenceArtifact,
  SecurityProvider,
  SecurityProviderMetadata,
  SecurityScanInput,
  SecurityScanResult,
  SecurityScanSummary,
  SecurityStage,
} from "@vibecontrols/vibe-plugin-security/types";

import { KUBE_BENCH_VERSION, TOOLS_MANIFEST, TRIVY_VERSION } from "./tools-manifest.js";

interface RuntimeConfig {
  images?: string[];
  kubeconfig?: string;
  registryAuth?: {
    server?: string;
    username?: string;
    password?: string;
  };
  skipKubeconfigProbe?: boolean; // testing
  extraTrivyArgs?: string[];
  extraKubeBenchArgs?: string[];
}

export class TrivyKubeBenchProvider implements SecurityProvider {
  readonly name = "trivy-kube-bench";
  readonly stage: SecurityStage = "runtime.continuous";
  readonly toolVersion = `trivy@${TRIVY_VERSION}+kube-bench@${KUBE_BENCH_VERSION}`;

  private host?: HostServices;
  private trivyPath?: string;
  private active = new Map<string, ChildProcess>();

  async init(host: HostServices): Promise<void> {
    this.host = host;
  }

  async ensureToolInstalled(): Promise<void> {
    const dataDir =
      this.host?.getDataDir?.() ?? path.join(process.env.HOME ?? ".", ".boff/vibecontrols");
    this.trivyPath = await resolveToolPath(
      {
        dataDir,
        log: {
          info: (m) => this.host?.logger?.info?.("runtime-provider", m),
          warn: (m) => this.host?.logger?.warn?.("runtime-provider", m),
          error: (m) => this.host?.logger?.error?.("runtime-provider", m),
        },
      },
      "trivy",
      TOOLS_MANIFEST.trivy,
    );
  }

  async run(input: SecurityScanInput): Promise<SecurityScanResult> {
    const startedAt = Date.now();
    const cfg = (input.config as RuntimeConfig) ?? {};

    input.onProgress?.({ pct: 5, message: "Probing kubeconfig" });

    // Skip path — kubeconfig missing / cluster unreachable.
    if (!cfg.skipKubeconfigProbe && !(await this.kubeconfigUsable(cfg.kubeconfig))) {
      return this.succeededSkipped(
        input,
        startedAt,
        "missing-cluster-access",
        "runtime.continuous: skipped — no kubeconfig present or cluster unreachable.",
      );
    }

    // TODO(wave-2): replace this stub with the real Trivy rescan + kube-bench
    // pipeline. Keep the result shape identical so the dispatcher does not
    // need to change.
    input.onProgress?.({ pct: 50, message: "runtime.continuous scaffold" });

    const fingerprint = createHash("sha256")
      .update(`${this.name}:${input.runId}:${(cfg.images ?? []).join(",")}`)
      .digest("hex");

    const findings: NormalizedFinding[] = [
      {
        fingerprint,
        ruleId: `${this.name}.stub`,
        title: "runtime.continuous: trivy-kube-bench scaffolded — real integration pending",
        severity: "info",
        category: "config",
        description:
          "Wave 2 scaffold for the runtime.continuous lifecycle stage. The real provider will run Trivy rescan against each deployed image (SARIF output) and kube-bench against the cluster nodes (JSON output), normalize both into NormalizedFindings, and emit them as evidence. Today this stub records that the stage ran so the dispatcher can chain the next stage.",
        remediation:
          "Wire the real Trivy + kube-bench subprocess pipeline; emit SARIF and JSON evidence artifacts.",
      },
    ];

    const evidence: ScanEvidenceArtifact[] = [];
    const summary: SecurityScanSummary = summarize(findings);

    input.onProgress?.({ pct: 100, message: "Scaffold run complete" });

    return {
      runId: input.runId,
      status: "succeeded",
      findings,
      evidence,
      durationMs: Date.now() - startedAt,
      summary,
    };
  }

  async cancel(runId: string): Promise<void> {
    const child = this.active.get(runId);
    if (!child) return;
    try {
      child.kill("SIGTERM");
      setTimeout(() => {
        try {
          child.kill("SIGKILL");
        } catch {
          /* already gone */
        }
      }, 5000);
    } finally {
      this.active.delete(runId);
    }
  }

  metadata(): SecurityProviderMetadata {
    return {
      stage: this.stage,
      supportedProfiles: ["backend", "frontend", "container", "iac"],
      toolVersion: this.toolVersion,
      description:
        "Trivy rescan + kube-bench for runtime.continuous (Wave 2 scaffold; real integration pending).",
    };
  }

  private async kubeconfigUsable(override?: string): Promise<boolean> {
    const kubeconfigPath =
      override ?? process.env.KUBECONFIG ?? path.join(process.env.HOME ?? "", ".kube", "config");
    if (!kubeconfigPath) return false;
    try {
      const stat = await fs.stat(kubeconfigPath);
      if (!stat.isFile()) return false;
    } catch {
      return false;
    }
    // Best-effort reachability: invoke `kubectl get nodes` quietly. We
    // don't assume kubectl is on PATH; absence is treated as unreachable.
    return new Promise((resolve) => {
      const child = spawn("kubectl", ["--kubeconfig", kubeconfigPath, "get", "nodes"], {
        stdio: ["ignore", "ignore", "ignore"],
      });
      child.on("close", (code) => resolve(code === 0));
      child.on("error", () => resolve(false));
    });
  }

  private succeededSkipped(
    input: SecurityScanInput,
    startedAt: number,
    reason: string,
    title: string,
  ): SecurityScanResult {
    const fingerprint = createHash("sha256")
      .update(`${this.name}:${input.runId}:${reason}`)
      .digest("hex");
    const findings: NormalizedFinding[] = [
      {
        fingerprint,
        ruleId: `${this.name}.skipped`,
        title,
        severity: "info",
        category: "config",
        description: `Skip reason: ${reason}. The provider returned successfully without performing a scan; the dispatcher should mark the run with conclusion "skipped".`,
      },
    ];
    return {
      runId: input.runId,
      status: "succeeded",
      findings,
      evidence: [],
      durationMs: Date.now() - startedAt,
      summary: summarize(findings),
    };
  }
}

function summarize(findings: NormalizedFinding[]): SecurityScanSummary {
  const s: SecurityScanSummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) s[f.severity]++;
  return s;
}
