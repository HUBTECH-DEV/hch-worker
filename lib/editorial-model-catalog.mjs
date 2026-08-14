/**
 * Canonical, version-controlled model releases. A model name is never paired
 * with a mutable or implicit digest: adding or changing a model requires a
 * reviewed source release and consequently a new signed worker manifest.
 */
export const EDITORIAL_MODEL_RELEASES = Object.freeze([
  Object.freeze({
    model: "qwen2.5:1.5b-instruct",
    digest: "65ec06548149b04c096a120e4a6da9d4017ea809c91734ea5631e89f96ddc57b",
    engineAdapter: "ollama",
    engineAdapterVersion: "1.0.0",
    supportedProtocols: Object.freeze(["hch-json", "ollama-chat"]),
  }),
]);

export function editorialModelRelease(model, protocol) {
  const normalizedModel = String(model ?? "").trim();
  const release = EDITORIAL_MODEL_RELEASES.find((item) => item.model === normalizedModel) ?? null;
  if (!release) return null;
  if (protocol && !release.supportedProtocols.includes(protocol)) return null;
  return release;
}
