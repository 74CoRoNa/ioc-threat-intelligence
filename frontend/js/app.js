import { apiPost } from "/js/api.js";
import { createElement } from "/js/render.js";

const form = document.querySelector("#ioc-form");
const input = document.querySelector("#ioc-value");
const button = form.querySelector("button");
const feedback = document.querySelector("#feedback");
const report = document.querySelector("#report");
const riskSummary = report.querySelector(".risk-summary");

const PROVIDERS = ["virustotal", "abuseipdb", "threatfox", "urlhaus"];

const LABELS = {
  virustotal: "VirusTotal",
  abuseipdb: "AbuseIPDB",
  threatfox: "ThreatFox",
  urlhaus: "URLhaus",
};

const STATES = {
  ok: "Success",
  not_configured: "Not configured",
  not_applicable: "Not applicable",
  rate_limited: "Rate limited",
  timeout: "Timeout",
  error: "Unavailable",
};

// Severity is always shown as a word; the tone only reinforces it.
const TONES = {
  LOW: "good",
  MODERATE: "warn",
  SUSPICIOUS: "sus",
  HIGH: "bad",
  CRITICAL: "critical",
};

function progress(state, text) {
  for (const tile of document.querySelectorAll("#provider-progress > div")) {
    tile.dataset.state = state;
    tile.querySelector("small").textContent = text;
  }
}

function display(value) {
  if (Array.isArray(value)) return value.length ? value.join(", ") : "None";
  if (value === null || value === undefined || value === "") return "Not returned";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return String(value);
}

function chip(label, tone) {
  const element = createElement("span", { className: "chip", text: label });
  if (tone) element.dataset.tone = tone;
  else element.classList.add("chip--plain");
  return element;
}

function renderProviders(data) {
  const root = document.querySelector("#provider-results");
  root.replaceChildren();

  for (const name of PROVIDERS) {
    const provider = data[name] || { status: "error", message: "Provider result missing." };
    const status = STATES[provider.status] || provider.status;
    const healthy = provider.status === "ok";
    const neutral = provider.status === "not_applicable" || provider.status === "not_configured";

    const tile = document.querySelector(`[data-provider="${name}"]`);
    if (tile) {
      tile.dataset.state = healthy ? "ok" : neutral ? "pending" : "error";
      tile.querySelector("small").textContent = status;
    }

    const card = createElement("article", { className: "provider-card" });
    card.dataset.state = healthy ? "ok" : neutral ? "neutral" : "error";

    const header = createElement("header");
    header.append(
      createElement("h3", { text: LABELS[name] }),
      createElement("span", { text: status }),
    );
    card.append(header);

    if (provider.message) {
      card.append(createElement("p", { className: "provider-message", text: provider.message }));
    }

    if (provider.external_url) {
      const link = createElement("a", {
        className: "provider-link",
        text: `View on ${LABELS[name]}`,
      });
      link.href = provider.external_url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      card.append(link);
    }

    const entries = Object.entries(provider.data || {}).filter(([, value]) => value !== null && value !== undefined);
    if (entries.length) {
      const list = createElement("dl");
      for (const [key, value] of entries) {
        const row = createElement("div");
        row.append(
          createElement("dt", { text: key.replaceAll("_", " ") }),
          createElement("dd", { text: display(value) }),
        );
        list.append(row);
      }
      card.append(list);
    }

    root.append(card);
  }
}

function renderEvidence(risk) {
  const list = document.querySelector("#evidence-list");
  list.replaceChildren();

  if (!risk.evidence.length) {
    list.append(createElement("li", { text: "No risk-increasing evidence was returned." }));
    return;
  }

  for (const item of risk.evidence) {
    const row = createElement("li");
    const weight = createElement("span", {
      className: "weight-chip",
      text: item.weight ? `+${item.weight}` : "0",
    });
    if (item.weight) weight.dataset.scored = "yes";
    row.append(weight, createElement("span", { text: item.description }));
    list.append(row);
  }
}

function render(data) {
  const result = data.result;
  if (data.status !== "ok" || !result || !result.risk_assessment) {
    feedback.textContent = data.error || "This indicator could not be analyzed.";
    progress("error", "Not completed");
    report.hidden = true;
    return;
  }

  const risk = result.risk_assessment;

  document.querySelector("#case-ioc").textContent = data.value;
  document.querySelector("#case-type").textContent = result.observed_port
    ? `${data.type.toUpperCase()} · port ${result.observed_port}`
    : data.type.toUpperCase();
  document.querySelector("#case-time").textContent = new Date().toLocaleString();
  document.querySelector("#case-status").textContent = "Completed";

  riskSummary.dataset.severity = risk.severity;
  document.querySelector("#risk-score").textContent = risk.score;
  document.querySelector("#risk-severity").textContent = `${risk.severity} risk`;
  document.querySelector("#risk-verdict").textContent = risk.verdict;
  document.querySelector("#risk-fill").style.width = `${risk.score}%`;

  const chips = document.querySelector("#risk-chips");
  chips.replaceChildren(
    chip(risk.severity, TONES[risk.severity]),
    chip(`${risk.sources_available}/${risk.sources_expected} sources`),
    chip(`${risk.confidence} confidence`),
  );

  document.querySelector("#correlation").textContent = risk.correlation;
  renderEvidence(risk);
  renderProviders(result.threat_intelligence || {});

  document.querySelector("#full-report").href =
    `/report.html?id=${encodeURIComponent(result.investigation_id)}`;

  report.hidden = false;
  report.scrollIntoView({ behavior: "smooth", block: "start" });
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  feedback.textContent = "";
  report.hidden = true;
  button.disabled = true;
  button.textContent = "Analyzing…";
  progress("pending", "Querying");

  try {
    render(await apiPost("/api/analyze/ioc", { value: input.value.trim() }));
  } catch (error) {
    feedback.textContent = error.message;
    progress("error", "Not completed");
  } finally {
    button.disabled = false;
    button.textContent = "Analyze";
  }
});
