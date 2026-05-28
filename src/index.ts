/**
 * @vibecontrols/vibe-plugin-security-runtime
 *
 * Continuous runtime checks for the `runtime.continuous` lifecycle stage.
 * Registers as a `security.runtime` provider (per PROVIDER_TYPE_FOR_STAGE)
 * with @vibecontrols/vibe-plugin-security on the host's ServiceRegistry.
 */
import { ProviderRegistry, TelemetryEmitter, createLifecycleHooks } from "@vibecontrols/plugin-sdk";
import type {
  HostServices,
  ProfileContext,
  VibePlugin,
  VibePluginFactory,
} from "@vibecontrols/plugin-sdk/contract";

import { TrivyKubeBenchProvider } from "./provider.js";

const PLUGIN_NAME = "security-runtime";
const PLUGIN_VERSION = "2026.528.6";

export const createPlugin: VibePluginFactory = (_ctx: ProfileContext): VibePlugin => {
  const provider = new TrivyKubeBenchProvider();
  const telemetry = new TelemetryEmitter(PLUGIN_NAME, PLUGIN_VERSION);

  const lifecycle = createLifecycleHooks({
    name: PLUGIN_NAME,
    telemetryEventName: "security.runtime.ready",
    onInit: async (host: HostServices) => {
      await provider.init(host);
      const registry = new ProviderRegistry(host);
      registry.registerProvider("security.runtime", "trivy-kube-bench", provider);
      telemetry.emit("security.runtime.registered", {
        provider: "trivy-kube-bench",
        toolVersion: provider.toolVersion,
      });
    },
  });

  return {
    name: PLUGIN_NAME,
    version: PLUGIN_VERSION,
    description:
      "Continuous Trivy image rescan + kube-bench CIS check for the runtime.continuous lifecycle stage. Trivy auto-installs via sha256-pinned binary; kube-bench runs as a Docker container against the configured kubeconfig.",
    tags: ["backend", "provider", "integration"],
    capabilities: {
      storage: "rw",
      subprocess: true,
      audit: true,
      telemetry: true,
    },
    onServerStart: lifecycle.onServerStart,
    onServerStop: lifecycle.onServerStop,
  };
};

export default createPlugin;
export { TrivyKubeBenchProvider } from "./provider.js";
