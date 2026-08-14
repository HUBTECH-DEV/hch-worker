const EXTERNAL_CLAIM_TYPES = new Set(["fact", "source-statement"]);

export function computeEditorialMetrics(paragraphs) {
  const texts = Array.isArray(paragraphs)
    ? paragraphs.map((paragraph) => String(paragraph?.text ?? "").trim()).filter(Boolean)
    : [];
  const body = texts.join("\n\n");
  const paragraphWords = texts.map(countWords);
  const externalClaims = (paragraphs ?? []).flatMap((paragraph) =>
    Array.isArray(paragraph?.claims)
      ? paragraph.claims.filter((claim) => EXTERNAL_CLAIM_TYPES.has(claim?.claimType))
      : [],
  );
  const supportedClaims = externalClaims.filter(
    (claim) => Array.isArray(claim?.sourceIds) && claim.sourceIds.length > 0,
  );
  const quotedWords = texts.reduce((total, text) => total + countQuotedWords(text), 0);
  const bodyWords = countWords(body);

  return {
    bodyCharacters: body.length,
    bodyWords,
    paragraphCount: texts.length,
    minimumParagraphWords: paragraphWords.length ? Math.min(...paragraphWords) : 0,
    citationCoverage: externalClaims.length
      ? supportedClaims.length / externalClaims.length
      : 1,
    unsupportedClaimCount: externalClaims.length - supportedClaims.length,
    directQuotationRatio: bodyWords ? quotedWords / bodyWords : 0,
  };
}

export function validateEditorialDraft(draft, policy) {
  const errors = [];
  if (!draft || typeof draft !== "object") {
    return fail("DOC-001", "O conteúdo editorial deve ser um objeto estruturado.");
  }
  if (!policy || typeof policy !== "object") {
    return fail("POL-001", "A política editorial não foi carregada.");
  }

  const paragraphs = Array.isArray(draft.paragraphs) ? draft.paragraphs : [];
  const sources = Array.isArray(draft.sources) ? draft.sources : [];
  const metrics = computeEditorialMetrics(paragraphs);
  const sourceIds = new Set(sources.map((source) => source?.sourceId).filter(Boolean));
  const profile = draft.editorialProfile;

  if (draft.locale !== "pt-BR") {
    errors.push(issue("LNG-001", "Todo conteúdo editorial do HCH deve estar em português brasileiro."));
  }

  if (typeof draft.title !== "string" || draft.title.trim().length < 8) {
    errors.push(issue("DOC-002", "O título deve ter pelo menos oito caracteres."));
  }
  if (typeof draft.excerpt !== "string" || draft.excerpt.trim().length < 20) {
    errors.push(issue("DOC-003", "O resumo deve ter pelo menos vinte caracteres."));
  }
  for (const [field, value] of [
    ["título", draft.title],
    ["resumo", draft.excerpt],
    ...paragraphs.map((paragraph, index) => [`parágrafo ${index + 1}`, paragraph?.text]),
  ]) {
    if (containsMarkupArtifacts(value)) {
      errors.push(issue("DOC-004", `O ${field} contém marcação HTML residual.`));
    }
  }
  if (!sources.length) {
    errors.push(issue("SRC-001", "Pelo menos uma fonte canônica é obrigatória."));
  }
  if (
    sources.length === 1 &&
    policy.citationPolicy?.singleSourceExceptionRequiresJustification &&
    (typeof draft.sourceSelectionJustification !== "string" ||
      draft.sourceSelectionJustification.trim().length < 30)
  ) {
    errors.push(issue("SRC-003", "A exceção de fonte única exige justificativa editorial."));
  }
  if (
    ["review", "comparison"].includes(draft.contentType) &&
    sources.length < Number(policy.citationPolicy?.comparisonsAndReviewsMinimumSources ?? 2)
  ) {
    errors.push(issue("SRC-004", "Reviews e comparações exigem pelo menos duas fontes."));
  }

  for (const source of sources) {
    if (!source?.sourceId || !/^S[1-9][0-9]*$/.test(source.sourceId)) {
      errors.push(issue("SRC-002", "Cada fonte deve possuir um identificador estável."));
    }
    if (!isHttpUrl(source?.canonicalUrl)) {
      errors.push(issue("SRC-001", "Cada fonte deve possuir URL canônica HTTP(S)."));
    }
    if (!source?.normalizedHash || !/^[a-f0-9]{64}$/i.test(source.normalizedHash)) {
      errors.push(issue("TRC-001", "A revisão normalizada da fonte é obrigatória."));
    }
    if (!source?.rightsBasis) {
      errors.push(issue("RGT-001", "A base de direitos deve ser registrada."));
    }
  }

  paragraphs.forEach((paragraph, index) => {
    if (containsStructuralMarkup(paragraph?.text)) {
      errors.push(issue("DOC-005", `O parágrafo ${index + 1} contém estrutura Markdown ou múltiplos blocos internos.`));
    }
    const citations = Array.isArray(paragraph?.citationIds)
      ? paragraph.citationIds
      : [];
    const claims = Array.isArray(paragraph?.claims) ? paragraph.claims : [];
    const externalClaims = claims.filter((claim) =>
      EXTERNAL_CLAIM_TYPES.has(claim?.claimType),
    );

    if (externalClaims.length && citations.length === 0) {
      errors.push(issue("CIT-001", `O parágrafo ${index + 1} contém fatos sem citação.`));
    }
    for (const citationId of citations) {
      if (!sourceIds.has(citationId)) {
        errors.push(issue("CIT-002", `A citação ${citationId} não resolve para uma fonte.`));
      }
      if (!String(paragraph?.text ?? "").includes(`[${citationId}]`)) {
        errors.push(issue("CIT-001", `A citação ${citationId} não aparece no texto do parágrafo.`));
      }
    }
    for (const claim of externalClaims) {
      const claimSources = Array.isArray(claim?.sourceIds) ? claim.sourceIds : [];
      if (!claimSources.length) {
        errors.push(issue("CIT-003", `A afirmação ${claim?.claimId ?? index + 1} não possui fonte.`));
      }
      for (const sourceId of claimSources) {
        if (!sourceIds.has(sourceId)) {
          errors.push(issue("CIT-002", `A afirmação referencia a fonte inexistente ${sourceId}.`));
        }
        if (!citations.includes(sourceId)) {
          errors.push(issue("CIT-001", `A fonte ${sourceId} da afirmação não está citada no parágrafo ${index + 1}.`));
        }
      }
    }
  });

  if (["EDITORIAL_LONG_FORM", "EDITORIAL_COMPACT", "EDITORIAL_MINIMUM"].includes(profile)) {
    const editorial = policy.profiles?.[profile] ?? {};
    minimum(errors, "LEN-001", metrics.bodyCharacters, editorial.minimumBodyCharacters, "caracteres");
    maximum(errors, "LEN-005", metrics.bodyCharacters, editorial.maximumBodyCharacters, "caracteres");
    minimum(errors, "LEN-002", metrics.bodyWords, editorial.minimumBodyWords, "palavras");
    maximum(errors, "LEN-006", metrics.bodyWords, editorial.maximumBodyWords, "palavras");
    minimum(errors, "LEN-003", metrics.paragraphCount, editorial.minimumParagraphs, "parágrafos");
    maximum(errors, "LEN-007", metrics.paragraphCount, editorial.maximumParagraphs, "parágrafos");
    minimum(errors, "LEN-004", metrics.minimumParagraphWords, editorial.minimumWordsPerParagraph, "palavras por parágrafo");
  } else if (profile === "CATALOG_SUMMARY" || profile === "EVENT_LISTING") {
    const summaryProfile = policy.profiles?.[profile] ?? {};
    exact(errors, "LEN-003", metrics.paragraphCount, summaryProfile.paragraphs, "parágrafos");
    minimum(errors, "LEN-001", metrics.bodyCharacters, summaryProfile.minimumCharacters, "caracteres");
    maximum(errors, "LEN-005", metrics.bodyCharacters, summaryProfile.maximumCharacters, "caracteres");
  }

  const maxQuoteRatio = Number(policy.quotationPolicy?.maximumQuotationRatio ?? 0.05);
  const maxQuoteWords = Number(policy.quotationPolicy?.maximumWordsPerDirectQuotation ?? 25);
  for (const quoteWords of directQuotationWordCounts(paragraphs)) {
    if (quoteWords > maxQuoteWords) {
      errors.push(issue("ORG-002", `Uma citação direta excede o limite de ${maxQuoteWords} palavras.`));
    }
  }
  if (metrics.directQuotationRatio > maxQuoteRatio) {
    errors.push(issue("ORG-001", "A proporção de citação direta excede o limite da política."));
  }
  if (metrics.unsupportedClaimCount > 0) {
    errors.push(issue("CIT-003", "Existem afirmações externas sem fonte."));
  }

  const provenance = draft.provenance ?? {};
  if (provenance.policyId !== policy.policyId || provenance.policyVersion !== policy.version) {
    errors.push(issue("TRC-001", "A versão da política não corresponde à geração."));
  }
  for (const field of [
    "promptConfigHash",
    "pipelineVersion",
    "modelProvider",
    "modelIdentifier",
    "generatedAt",
  ]) {
    if (!provenance[field]) {
      errors.push(issue("TRC-001", `O campo de rastreabilidade ${field} é obrigatório.`));
    }
  }

  return { valid: errors.length === 0, errors: uniqueIssues(errors), metrics };
}

export function validatePublicationReadiness({
  draft,
  policy,
  review,
  sourceRevisionMatches,
}) {
  const validation = validateEditorialDraft(draft, policy);
  const errors = [...validation.errors];
  if (!sourceRevisionMatches) {
    errors.push(issue("PUB-001", "A fonte mudou depois da geração; gere uma nova revisão."));
  }
  if (review?.status !== "approved" || !review?.reviewedBy || !review?.reviewedAt) {
    errors.push(issue("REV-001", "A revisão editorial humana ainda não foi aprovada."));
  }
  if (!review?.rightsApproved) {
    errors.push(issue("RGT-001", "A revisão de direitos ainda não foi aprovada."));
  }
  if (!review?.citationsApproved) {
    errors.push(issue("CIT-001", "A revisão de citações ainda não foi aprovada."));
  }
  if (!review?.originalityApproved) {
    errors.push(issue("ORG-001", "A revisão de originalidade ainda não foi aprovada."));
  }
  return {
    valid: errors.length === 0,
    errors: uniqueIssues(errors),
    metrics: validation.metrics,
  };
}

function minimum(errors, code, actual, expected, unit) {
  if (Number.isFinite(expected) && actual < expected) {
    errors.push(issue(code, `Mínimo de ${expected} ${unit}; resultado atual: ${actual}.`));
  }
}

function maximum(errors, code, actual, expected, unit) {
  if (Number.isFinite(expected) && actual > expected) {
    errors.push(issue(code, `Máximo de ${expected} ${unit}; resultado atual: ${actual}.`));
  }
}

function exact(errors, code, actual, expected, unit) {
  if (Number.isFinite(expected) && actual !== expected) {
    errors.push(issue(code, `Quantidade obrigatória: ${expected} ${unit}; resultado atual: ${actual}.`));
  }
}

function countWords(value) {
  return String(value ?? "").trim().match(/[\p{L}\p{N}][\p{L}\p{N}'’_-]*/gu)?.length ?? 0;
}

function countQuotedWords(value) {
  const matches = String(value ?? "").matchAll(/[“"]([^”"]+)[”"]/g);
  let total = 0;
  for (const match of matches) total += countWords(match[1]);
  return total;
}

function directQuotationWordCounts(paragraphs) {
  const counts = [];
  for (const paragraph of paragraphs ?? []) {
    const matches = String(paragraph?.text ?? "").matchAll(/[“"]([^”"]+)[”"]/g);
    for (const match of matches) counts.push(countWords(match[1]));
  }
  return counts;
}

function isHttpUrl(value) {
  try {
    const url = new URL(String(value ?? ""));
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function containsMarkupArtifacts(value) {
  const text = String(value ?? "");
  return (
    /<\/?[a-z][^>]*>/i.test(text) ||
    /&(?:amp;)*lt;\/?[a-z][\s\S]*?&(?:amp;)*gt;/i.test(text)
  );
}

function containsStructuralMarkup(value) {
  const text = String(value ?? "");
  return (
    /\n\s*\n/.test(text) ||
    /(^|\n)\s*#{1,6}\s+/m.test(text) ||
    /(^|\n)\s*(?:[-*+]\s+|\d+\.\s+)/m.test(text) ||
    /\*\*[^*]+\*\*|__[^_]+__|`{1,3}[^`]+`{1,3}/.test(text) ||
    /\[[^\]]+\]\(https?:\/\//i.test(text)
  );
}

function issue(code, message) {
  return { code, message };
}

function fail(code, message) {
  return {
    valid: false,
    errors: [issue(code, message)],
    metrics: computeEditorialMetrics([]),
  };
}

function uniqueIssues(errors) {
  return errors.filter(
    (entry, index, collection) =>
      collection.findIndex(
        (candidate) => candidate.code === entry.code && candidate.message === entry.message,
      ) === index,
  );
}
