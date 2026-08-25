export function clearElement(element) {
  element.replaceChildren();
}

export function createElement(tagName, options = {}) {
  const element = document.createElement(tagName);
  if (options.className) {
    element.className = options.className;
  }
  if (options.text !== undefined) {
    element.textContent = String(options.text);
  }
  return element;
}

export function showError(container, message) {
  clearElement(container);
  container.append(
    createElement("p", {
      className: "error-banner",
      text: message,
    }),
  );
}

/**
 * Map a verdict to a chip tone. Deliberately keyed on the verdict rather than
 * the score: "No Known Threat Intelligence" is an absence of findings, not a
 * clean bill of health, so it stays neutral instead of reading as safe.
 */
export const VERDICT_TONES = {
  "Confirmed Malicious": "critical",
  "Highly Suspicious": "bad",
  Suspicious: "warn",
};

export function createVerdictChip(verdict) {
  const chip = createElement("span", { className: "chip", text: verdict || "Not scored" });
  const tone = VERDICT_TONES[verdict];
  if (tone) chip.dataset.tone = tone;
  else chip.classList.add("chip--plain");
  return chip;
}

export function createBadge(label, muted = false) {
  return createElement("span", {
    className: muted ? "badge badge--muted" : "badge",
    text: label,
  });
}

export function createResultCard(title, entries, options = {}) {
  const card = createElement("article", {
    className: options.wide ? "result-card result-card--wide" : "result-card",
  });
  card.append(createElement("h2", { text: title }));

  if (options.badges?.length) {
    const badges = createElement("div", { className: "badge-row" });
    for (const badge of options.badges) {
      badges.append(createBadge(badge.label, badge.muted));
    }
    card.append(badges);
  }

  const list = createElement("dl", { className: "key-values" });
  for (const [label, rawValue] of entries) {
    const row = createElement("div", { className: "key-value" });
    const value = rawValue ?? "Not available";
    row.append(createElement("dt", { text: label }));

    const description = createElement("dd");
    if (options.copyValues && rawValue !== null && rawValue !== undefined) {
      description.className = "copy-value";
      description.append(createElement("span", { text: value }));
      const copyButton = createElement("button", {
        className: "copy-button",
        text: "Copy",
      });
      copyButton.type = "button";
      copyButton.addEventListener("click", async () => {
        await navigator.clipboard.writeText(String(value));
        copyButton.textContent = "Copied";
        window.setTimeout(() => {
          copyButton.textContent = "Copy";
        }, 1200);
      });
      description.append(copyButton);
    } else {
      description.textContent = String(value);
    }

    row.append(description);
    list.append(row);
  }

  card.append(list);
  if (options.externalUrl?.startsWith("https://")) {
    const link = createElement("a", {
      className: "provider-link",
      text: "View provider report ↗",
    });
    link.href = options.externalUrl;
    link.target = "_blank";
    link.rel = "noreferrer noopener";
    card.append(link);
  }
  return card;
}

export function createProviderCard(provider) {
  const entries = [["Status", provider.status.replaceAll("_", " ")]];
  if (provider.message) {
    entries.push(["Message", provider.message]);
  }
  for (const [key, rawValue] of Object.entries(provider.data || {})) {
    if (rawValue === null || rawValue === undefined || typeof rawValue === "object" && !Array.isArray(rawValue)) {
      continue;
    }
    const value = Array.isArray(rawValue) ? rawValue.join(", ") || "None" : rawValue;
    entries.push([key.replaceAll("_", " "), value]);
  }
  return createResultCard(
    provider.source === "rdap" ? "RDAP / ASN" : provider.source,
    entries,
    {
      badges: [
        { label: provider.status, muted: provider.status !== "ok" },
        ...(provider.cached ? [{ label: "Cached", muted: true }] : []),
      ],
      externalUrl: provider.external_url,
    },
  );
}

export function createRiskCard(risk) {
  const card = createElement("article", {
    className: `result-card result-card--wide risk-panel risk-panel--${risk.verdict.toLowerCase()}`,
  });
  const heading = createElement("div", { className: "risk-heading" });
  const titleGroup = createElement("div");
  titleGroup.append(
    createElement("p", { className: "eyebrow", text: "Risk Assessment" }),
    createElement("h2", { text: risk.statement }),
  );
  const score = createElement("strong", {
    className: "risk-score",
    text: `${risk.score}/100`,
  });
  heading.append(titleGroup, score);

  const track = createElement("div", { className: "risk-track" });
  const fill = createElement("span", { className: "risk-fill" });
  fill.style.width = `${risk.score}%`;
  track.append(fill);

  const badges = createElement("div", { className: "badge-row" });
  badges.append(
    createBadge(risk.verdict),
    createBadge(`Confidence: ${risk.confidence}`, risk.confidence !== "high"),
    createBadge(`${risk.sources_available}/${risk.sources_expected} sources`, true),
  );
  card.append(heading, track, badges);

  const evidence = createElement("dl", { className: "key-values" });
  if (!risk.evidence.length) {
    const row = createElement("div", { className: "key-value" });
    row.append(
      createElement("dt", { text: "Evidence" }),
      createElement("dd", { text: "No risk-increasing evidence was available." }),
    );
    evidence.append(row);
  } else {
    for (const item of risk.evidence) {
      const row = createElement("div", { className: "key-value" });
      row.append(
        createElement("dt", { text: `${item.source} · +${item.weight}` }),
        createElement("dd", { text: item.description }),
      );
      evidence.append(row);
    }
  }
  card.append(evidence);
  return card;
}

export function createReportButton(investigationId) {
  const link = createElement("a", {
    className: "report-button",
    text: "Generate Report",
  });
  link.href = `/report.html?id=${encodeURIComponent(investigationId)}`;
  return link;
}
