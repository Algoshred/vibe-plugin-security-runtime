/**
 * TrivyKubeBenchProvider — implements SecurityProvider for stage
 * `runtime.continuous`.
 *
 * Two independent tools run inside a single provider:
 *
 *   1. **Trivy image rescans** — for every imageRef in `input.config.imageRefs`,
 *      spawn the pinned Trivy binary with `--format json` and parse the per-CVE
 *      vulnerabilities into NormalizedFinding[] (category "vuln"). The Trivy
 *      binary auto-installs via the shared tool-installer (sha256-pinned per
 *      platform in `./tools-manifest.ts`). Empty `imageRefs` is **not** an
 *      error: the provider emits one info finding `trivy.no-images-configured`
 *      and moves on.
 *
 *   2. **kube-bench CIS check** — when a kubeconfig is resolvable (config
 *      override → `$KUBECONFIG` → `~/.kube/config`) AND Docker is available
 *      on the host, run the `aquasec/kube-bench:latest` image as a one-shot
 *      container with `--json` output and normalise FAIL results into
 *      NormalizedFinding[] (category "config"). Missing docker, missing
 *      kubeconfig, or `runKubeBench: false` each emit a single
 *      `kube-bench.skipped` info finding instead of failing the run.
 *
 * Either tool can independently emit a skip-with-reason finding without
 * blocking the other — the dispatcher records `conclusion: pass | warn |
 * fail` from the aggregated severity counts.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import type { HostServices } from "@vibecontrols/plugin-sdk/contract";
import { resolveToolPath } from "@vibecontrols/vibe-plugin-security/tool-installer";
import type {
  NormalizedFinding,
  ScanEvidenceArtifact,
  SecurityFindingCategory,
  SecurityProvider,
  SecurityProviderMetadata,
  SecurityScanInput,
  SecurityScanResult,
  SecurityScanSummary,
  SecurityStage,
  SecuritySeverity,
} from "@vibecontrols/vibe-plugin-security/types";

import {
  KUBE_BENCH_IMAGE,
  KUBE_BENCH_VERSION,
  TOOLS_MANIFEST,
  TRIVY_VERSION,
} from "./tools-manifest.js";

const TRIVY_TIMEOUT_MS = 10 * 60 * 1000;
const KUBE_BENCH_TIMEOUT_MS = 10 * 60 * 1000;

const TRIVY_SEVERITY_MAP: Record<string, SecuritySeverity> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  UNKNOWN: "info",
};

interface RuntimeConfig {
  imageRefs?: string[];
  kubeconfigPath?: string;
  runKubeBench?: boolean;
  trivySeverityFilter?: string;
  // Testing seam: lets unit tests bypass actual spawns.
  skipKubeconfigProbe?: boolean;
}

interface TrivyReport {
  Results?: Array<{
    Target?: string;
    Vulnerabilities?: TrivyVulnerability[] | null;
  }>;
}

interface TrivyVulnerability {
  VulnerabilityID?: string;
  Severity?: string;
  PkgName?: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Title?: string;
  Description?: string;
  References?: string[];
}

interface KubeBenchReport {
  Controls?: Array<{
    tests?: Array<{
      results?: Array<{
        test_id?: string;
        test_desc?: string;
        status?: string;
        scored?: boolean;
        remediation?: string;
      }>;
    }>;
  }>;
}

export class TrivyKubeBenchProvider implements SecurityProvider {
  readonly name = "trivy-kube-bench";
  readonly stage: SecurityStage = "runtime.continuous";
  readonly toolVersion = `trivy@${TRIVY_VERSION}+kube-bench@${KUBE_BENCH_VERSION}`;

  private host?: HostServices;
  private trivyPath?: string;
  private kubeBenchAvailable = false;
  private active = new Map<string, ChildProcess>();

  async init(host: HostServices): Promise<void> {
    this.host = host;
  }

  async ensureToolInstalled(): Promise<void> {
    const dataDir =
      this.host?.getDataDir?.() ?? path.join(process.env.HOME ?? ".", ".boff/vibecontrols");

    // 1. Trivy — sha256-pinned binary via the shared installer.
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

    // 2. kube-bench — Docker-based one-shot. Pre-warm the image if Docker is
    //    available; flag unavailable otherwise. `docker info` is cheap and
    //    reports both daemon presence + reachability.
    this.kubeBenchAvailable = await this.dockerInfoOk();
    if (this.kubeBenchAvailable) {
      try {
        await this.dockerPullKubeBench();
      } catch (err) {
        this.host?.logger?.warn?.(
          "runtime-provider",
          `kube-bench image pre-pull failed: ${String(err)}`,
        );
      }
    } else {
      this.host?.logger?.info?.(
        "runtime-provider",
        "docker not available — kube-bench checks will emit skip findings",
      );
    }
  }

  async run(input: SecurityScanInput): Promise<SecurityScanResult> {
    const startedAt = Date.now();
    if (!this.trivyPath) {
      await this.ensureToolInstalled();
    }

    const cfg = (input.config as RuntimeConfig) ?? {};
    const findings: NormalizedFinding[] = [];
    const evidence: ScanEvidenceArtifact[] = [];

    input.onProgress?.({ pct: 5, message: "Starting runtime checks" });

    // ── Trivy image rescans ────────────────────────────────────────────
    const imageRefs = cfg.imageRefs ?? [];
    if (imageRefs.length === 0) {
      findings.push(
        makeSkipFinding({
          ruleId: "trivy.no-images-configured",
          title: "Trivy image rescan skipped — no imageRefs configured",
          category: "vuln",
          description:
            "RuntimeConfig.imageRefs is empty; nothing to rescan. Add deployed image references to enable Trivy rescans.",
          fpInput: `trivy:no-images:${input.runId}`,
        }),
      );
    } else {
      const severityFilter = cfg.trivySeverityFilter ?? "HIGH,CRITICAL";
      const total = imageRefs.length;
      for (let i = 0; i < total; i++) {
        const imageRef = imageRefs[i];
        const pct = 10 + Math.floor(((i + 1) / total) * 55);
        input.onProgress?.({ pct, message: `Trivy: scanning ${imageRef}` });
        const slug = slugify(imageRef);
        const outputPath = path.join(input.workdir, `trivy-${slug}.json`);
        const args = [
          "image",
          "--format",
          "json",
          "--output",
          outputPath,
          "--severity",
          severityFilter,
          "--quiet",
          imageRef,
        ];
        const trivyResult = await this.spawnAndWait(
          `${input.runId}::trivy::${slug}`,
          this.trivyPath as string,
          args,
          {},
          TRIVY_TIMEOUT_MS,
        );
        if (trivyResult.code !== 0) {
          findings.push(
            makeSkipFinding({
              ruleId: "trivy.scan-failed",
              title: `Trivy scan failed for ${imageRef}`,
              category: "vuln",
              description: `Trivy exited ${trivyResult.code}: ${trivyResult.stderr.slice(0, 500)}`,
              severity: "low",
              fpInput: `trivy:scan-failed:${imageRef}:${trivyResult.code}`,
            }),
          );
          continue;
        }
        try {
          const raw = await fs.readFile(outputPath, "utf-8");
          const parsed = JSON.parse(raw) as TrivyReport;
          for (const result of parsed.Results ?? []) {
            for (const v of result.Vulnerabilities ?? []) {
              findings.push(normaliseTrivyVuln(v, imageRef));
            }
          }
          const stat = await fs.stat(outputPath);
          const sha256 = createHash("sha256").update(raw).digest("hex");
          // TODO(evidence-types): add dedicated `trivy-json` SecurityEvidenceType
          // to vibe-plugin-security/types. Until then, repurpose `grype-json`
          // since both are sha256-pinned vuln JSON reports.
          evidence.push({
            type: "grype-json",
            localPath: outputPath,
            sha256,
            sizeBytes: stat.size,
          });
        } catch (err) {
          this.host?.logger?.warn?.(
            "runtime-provider",
            `failed to parse trivy report for ${imageRef}: ${String(err)}`,
          );
        }
      }
    }

    // ── kube-bench check ───────────────────────────────────────────────
    const runKubeBench = cfg.runKubeBench !== false;
    if (!runKubeBench) {
      findings.push(
        makeSkipFinding({
          ruleId: "kube-bench.skipped",
          title: "kube-bench skipped — runKubeBench=false",
          category: "config",
          description: "RuntimeConfig.runKubeBench was set to false; skipping cluster CIS check.",
          fpInput: `kube-bench:disabled:${input.runId}`,
        }),
      );
    } else if (cfg.skipKubeconfigProbe) {
      // Test seam — fall through without docker spawn.
      findings.push(
        makeSkipFinding({
          ruleId: "kube-bench.skipped",
          title: "kube-bench skipped — skipKubeconfigProbe (test mode)",
          category: "config",
          description: "skipKubeconfigProbe=true; no docker spawn performed.",
          fpInput: `kube-bench:test-skip:${input.runId}`,
        }),
      );
    } else {
      input.onProgress?.({ pct: 75, message: "kube-bench: resolving kubeconfig" });
      const kubeconfigPath = resolveKubeconfigPath(cfg.kubeconfigPath);
      const kubeconfigUsable = kubeconfigPath ? await pathReadable(kubeconfigPath) : false;
      if (!kubeconfigUsable || !this.kubeBenchAvailable) {
        const reason = !kubeconfigUsable ? "missing-cluster-access" : "docker-unavailable";
        findings.push(
          makeSkipFinding({
            ruleId: "kube-bench.skipped",
            title: `kube-bench skipped — ${reason}`,
            category: "config",
            description:
              reason === "missing-cluster-access"
                ? `Kubeconfig not found at ${kubeconfigPath ?? "<unresolved>"}. Set RuntimeConfig.kubeconfigPath or KUBECONFIG env var.`
                : "Docker is not available on the host; kube-bench runs as a Docker container.",
            fpInput: `kube-bench:${reason}:${input.runId}`,
          }),
        );
      } else {
        input.onProgress?.({ pct: 80, message: "kube-bench: running container" });
        const outputPath = path.join(input.workdir, "kube-bench.json");
        const dockerArgs = [
          "run",
          "--rm",
          "-v",
          `${kubeconfigPath as string}:/root/.kube/config:ro`,
          KUBE_BENCH_IMAGE,
          "--json",
        ];
        const kb = await this.spawnAndWait(
          `${input.runId}::kube-bench`,
          "docker",
          dockerArgs,
          {},
          KUBE_BENCH_TIMEOUT_MS,
        );
        if (kb.code !== 0 && !kb.stdout) {
          findings.push(
            makeSkipFinding({
              ruleId: "kube-bench.scan-failed",
              title: "kube-bench scan failed",
              category: "config",
              description: `docker run exited ${kb.code}: ${kb.stderr.slice(0, 500)}`,
              severity: "low",
              fpInput: `kube-bench:failed:${input.runId}:${kb.code}`,
            }),
          );
        } else {
          try {
            await fs.writeFile(outputPath, kb.stdout);
            const parsed = JSON.parse(kb.stdout) as KubeBenchReport;
            for (const control of parsed.Controls ?? []) {
              for (const t of control.tests ?? []) {
                for (const r of t.results ?? []) {
                  if (r.status !== "FAIL") continue;
                  findings.push(normaliseKubeBenchResult(r));
                }
              }
            }
            const stat = await fs.stat(outputPath);
            const sha256 = createHash("sha256").update(kb.stdout).digest("hex");
            // TODO(evidence-types): add `kube-bench-json` SecurityEvidenceType.
            // Until then, repurpose `opa-decision` since both are sha256-pinned
            // JSON policy/config decisions.
            evidence.push({
              type: "opa-decision",
              localPath: outputPath,
              sha256,
              sizeBytes: stat.size,
            });
          } catch (err) {
            this.host?.logger?.warn?.(
              "runtime-provider",
              `failed to parse kube-bench output: ${String(err)}`,
            );
          }
        }
      }
    }

    input.onProgress?.({ pct: 100, message: "Runtime checks complete" });
    const summary: SecurityScanSummary = summarize(findings);

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
    for (const [key, child] of this.active.entries()) {
      if (!key.startsWith(runId)) continue;
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
        this.active.delete(key);
      }
    }
  }

  metadata(): SecurityProviderMetadata {
    return {
      stage: this.stage,
      supportedProfiles: ["backend", "frontend", "container", "iac"],
      toolVersion: this.toolVersion,
      description:
        "Trivy image rescan (--format json, sha256-pinned binary) + kube-bench CIS check via Docker. Each tool emits a skip-with-reason info finding when its prerequisites are missing.",
    };
  }

  private async dockerInfoOk(): Promise<boolean> {
    return new Promise((resolve) => {
      const child = spawn("docker", ["info"], { stdio: ["ignore", "ignore", "ignore"] });
      child.on("close", (code) => resolve(code === 0));
      child.on("error", () => resolve(false));
    });
  }

  private async dockerPullKubeBench(): Promise<void> {
    return new Promise((resolve, reject) => {
      const child = spawn("docker", ["pull", KUBE_BENCH_IMAGE], {
        stdio: ["ignore", "pipe", "pipe"],
      });
      let stderr = "";
      child.stderr.on("data", (b: Buffer) => (stderr += b.toString()));
      child.on("close", (code) =>
        code === 0 ? resolve() : reject(new Error(`docker pull exit ${code}: ${stderr}`)),
      );
      child.on("error", (err) => reject(err));
    });
  }

  private spawnAndWait(
    key: string,
    cmd: string,
    args: string[],
    env: NodeJS.ProcessEnv,
    timeoutMs: number,
  ): Promise<{ code: number | null; stdout: string; stderr: string }> {
    return new Promise((resolve) => {
      const child = spawn(cmd, args, {
        stdio: ["ignore", "pipe", "pipe"],
        env: { ...process.env, ...env },
      });
      this.active.set(key, child);
      let stdout = "";
      let stderr = "";
      child.stdout?.on("data", (b: Buffer) => (stdout += b.toString()));
      child.stderr?.on("data", (b: Buffer) => (stderr += b.toString()));
      const timer = setTimeout(() => {
        try {
          child.kill("SIGTERM");
        } catch {
          /* ignore */
        }
      }, timeoutMs);
      child.on("close", (code) => {
        clearTimeout(timer);
        this.active.delete(key);
        resolve({ code, stdout, stderr });
      });
      child.on("error", (err) => {
        clearTimeout(timer);
        this.active.delete(key);
        resolve({ code: -1, stdout, stderr: err.message });
      });
    });
  }
}

function resolveKubeconfigPath(override?: string): string | null {
  if (override) return override;
  if (process.env.KUBECONFIG) return process.env.KUBECONFIG;
  const home = process.env.HOME ?? os.homedir();
  return home ? path.join(home, ".kube", "config") : null;
}

async function pathReadable(p: string): Promise<boolean> {
  try {
    const stat = await fs.stat(p);
    return stat.isFile();
  } catch {
    return false;
  }
}

function normaliseTrivyVuln(v: TrivyVulnerability, imageRef: string): NormalizedFinding {
  const vid = v.VulnerabilityID ?? "TRIVY-UNKNOWN";
  const severity = TRIVY_SEVERITY_MAP[(v.Severity ?? "").toUpperCase()] ?? "info";
  const title = (v.Title ?? vid).slice(0, 200);
  const description = truncate(v.Description ?? "", 500);
  return {
    fingerprint: sha256Hex(`trivy:${imageRef}:${vid}`),
    ruleId: `trivy.${vid}`,
    title,
    description,
    severity,
    category: "vuln",
    cve: vid,
    packageName: v.PkgName,
    packageVersion: v.InstalledVersion,
    fixedVersion: v.FixedVersion,
    remediation: v.FixedVersion ? `Upgrade ${v.PkgName} to ${v.FixedVersion} or later.` : undefined,
    rawProviderRef: `image=${imageRef}`,
  };
}

function normaliseKubeBenchResult(
  r: NonNullable<
    NonNullable<NonNullable<KubeBenchReport["Controls"]>[number]["tests"]>[number]["results"]
  >[number],
): NormalizedFinding {
  const id = r.test_id ?? "kb-unknown";
  const severity: SecuritySeverity = r.scored ? "high" : "low";
  return {
    fingerprint: sha256Hex(`kube-bench:${id}`),
    ruleId: `kube-bench.${id}`,
    title: r.test_desc ?? `kube-bench ${id} failed`,
    description: r.remediation,
    severity,
    category: "config",
    remediation: r.remediation,
  };
}

interface SkipFindingInput {
  ruleId: string;
  title: string;
  category: SecurityFindingCategory;
  description: string;
  severity?: SecuritySeverity;
  fpInput: string;
}

function makeSkipFinding(i: SkipFindingInput): NormalizedFinding {
  return {
    fingerprint: sha256Hex(i.fpInput),
    ruleId: i.ruleId,
    title: i.title,
    description: i.description,
    severity: i.severity ?? "info",
    category: i.category,
  };
}

function slugify(s: string): string {
  return s.replace(/[^a-zA-Z0-9.-]+/g, "_").slice(0, 80);
}

function truncate(s: string, max: number): string {
  if (!s) return s;
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

function sha256Hex(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

function summarize(findings: NormalizedFinding[]): SecurityScanSummary {
  const s: SecurityScanSummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) s[f.severity]++;
  return s;
}
