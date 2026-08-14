/**
 * Canonical text representation used by signed release artifacts.
 *
 * Git and host checkouts may materialize the same text blob with LF, CRLF, or
 * (for older tooling) lone CR separators. Release hashes and served bytes must
 * not depend on that checkout detail, so every text artifact crosses this
 * boundary before it is hashed, embedded in a manifest, or served.
 */
export function canonicalLfText(value) {
  return String(value).replace(/\r\n?/g, "\n");
}
