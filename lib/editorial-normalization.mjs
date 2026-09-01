const SUMMARY_LIMITS = {
  EDITORIAL_COMPACT: { minimum: 450, maximum: 900 },
  EDITORIAL_MINIMUM: { minimum: 320, maximum: 800, maximumWords: 115 },
  EVENT_LISTING: { minimum: 220, maximum: 500 },
  CATALOG_SUMMARY: { minimum: 240, maximum: 480 },
};

const SOURCE_CITATION = "[S1]";

export function fitGeneratedParagraphToProfile(value, profile) {
  const text = String(value ?? "").trim();
  const limits = SUMMARY_LIMITS[profile];
  if (!limits || !text) return text;

  let body = text.replace(/\s*\[S1\]\s*$/i, "").trim();
  if (Number.isSafeInteger(limits.maximumWords)) {
    // The stable source citation contributes one policy-counted token.
    const maximumBodyWords = Math.max(1, limits.maximumWords - 1);
    const words = [...body.matchAll(/[\p{L}\p{N}][\p{L}\p{N}'’_-]*/gu)];
    if (words.length > maximumBodyWords) {
      const last = words[maximumBodyWords - 1];
      const end = Number(last.index) + last[0].length;
      body = `${body.slice(0, end).replace(/[,:;\-]+$/u, "").trim()}…`;
    }
  }
  const cited = `${body} ${SOURCE_CITATION}`;
  if (cited.length <= limits.maximum) return cited;

  const citationSuffix = ` ${SOURCE_CITATION}`;
  const sentenceBudget = limits.maximum - citationSuffix.length;
  const sentenceCandidate = body.slice(0, sentenceBudget);
  const sentenceEnd = Math.max(
    sentenceCandidate.lastIndexOf("."),
    sentenceCandidate.lastIndexOf("!"),
    sentenceCandidate.lastIndexOf("?"),
  );
  if (sentenceEnd + 1 >= limits.minimum) {
    return `${sentenceCandidate.slice(0, sentenceEnd + 1).trim()}${citationSuffix}`;
  }

  const ellipsisSuffix = `… ${SOURCE_CITATION}`;
  const wordBudget = limits.maximum - ellipsisSuffix.length;
  const wordCandidate = body.slice(0, wordBudget + 1);
  const wordEnd = wordCandidate.lastIndexOf(" ");
  const truncated = (
    wordEnd >= limits.minimum
      ? wordCandidate.slice(0, wordEnd)
      : body.slice(0, wordBudget)
  ).trim();
  return `${truncated}${ellipsisSuffix}`;
}
