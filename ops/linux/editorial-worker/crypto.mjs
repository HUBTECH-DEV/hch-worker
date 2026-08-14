export * from "../../../lib/editorial-worker-signatures.mjs";

export async function sha256Hex(value) {
  const bytes = typeof value === "string"
    ? new TextEncoder().encode(value)
    : value instanceof ArrayBuffer
      ? new Uint8Array(value)
      : ArrayBuffer.isView(value)
        ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
        : null;
  if (!bytes) throw new TypeError("SHA-256 input must be text or bytes.");
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}
