import { apiPost, setLoading } from "/js/api.js";
import { clearElement, createProviderCard, createReportButton, createResultCard, createRiskCard, showError } from "/js/render.js";

const form = document.querySelector("#target-form");
const feedback = document.querySelector("#feedback");
const results = document.querySelector("#results");
const submitButton = form.querySelector("button[type='submit']");

function formatRecord(record) {
  if (typeof record === "string") {
    return record;
  }
  return Object.entries(record)
    .map(([key, value]) => `${key}: ${value}`)
    .join(" · ");
}

function dnsEntries(dns) {
  return Object.entries(dns.records).map(([recordType, recordSet]) => {
    const value = recordSet.status === "ok"
      ? recordSet.records.map(formatRecord).join(" | ")
      : recordSet.message || recordSet.status.replaceAll("_", " ");
    return [recordType, value];
  });
}

function renderDomain(data) {
  results.append(
    createResultCard(
      "Domain Summary",
      [
        ["Domain", data.domain],
        ["Unicode form", data.unicode_domain],
        ["Registered domain", data.registered_domain],
        ["Subdomain", data.subdomain],
        ["Punycode", data.punycode ? "Yes" : "No"],
      ],
      { badges: [{ label: "Domain" }] },
    ),
    createResultCard("DNS Records", dnsEntries(data.dns), { wide: true }),
  );
  renderProviders(data.threat_intelligence);
  renderRisk(data.risk_assessment);
}

function renderURL(data) {
  const query = data.query_parameters.length
    ? data.query_parameters.map(({ name, value }) => `${name}=${value}`).join(" · ")
    : "None";
  results.append(
    createResultCard(
      "URL Breakdown",
      [
        ["Refanged URL", data.refanged],
        ["Scheme", data.scheme],
        ["Host", data.host],
        ["Port", data.port],
        ["Path", data.path],
        ["Query parameters", query],
        ["Fragment", data.fragment || "None"],
        ["Registered domain", data.registered_domain],
        ["Subdomain", data.subdomain],
        ["HTTPS", data.https ? "Yes" : "No"],
      ],
      { badges: [{ label: "URL" }, { label: data.https ? "HTTPS" : "HTTP", muted: !data.https }] },
    ),
    createResultCard(
      "Suspicious Pattern Flags",
      data.flags.length
        ? data.flags.map((flag) => [flag.code.replaceAll("_", " "), flag.description])
        : [["Result", "No configured suspicious URL patterns matched."]],
    ),
  );
  if (data.dns) {
    results.append(createResultCard("Host DNS Records", dnsEntries(data.dns), { wide: true }));
  }
  results.append(
    createResultCard(
      "Disabled in v1",
      [
        ["TLS inspection", data.disabled_features.tls],
        ["Redirect following", data.disabled_features.redirect_chain],
      ],
      { wide: true, badges: [{ label: "SSRF protection", muted: true }] },
    ),
  );
  renderProviders(data.threat_intelligence);
  renderRisk(data.risk_assessment);
}

function renderProviders(providers) {
  for (const provider of Object.values(providers || {})) {
    results.append(createProviderCard(provider));
  }
}

function renderRisk(risk) {
  if (risk) {
    results.prepend(createRiskCard(risk));
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearElement(feedback);
  clearElement(results);
  setLoading(submitButton, true, "Analyzing…");

  try {
    const formData = new FormData(form);
    const analysis = await apiPost("/api/analyze/target", {
      target: formData.get("target"),
    });
    if (analysis.target_type === "url") {
      renderURL(analysis.result);
    } else {
      renderDomain(analysis.result);
    }
    results.append(createReportButton(analysis.investigation_id));
  } catch (error) {
    showError(feedback, error.message);
  } finally {
    setLoading(submitButton, false);
  }
});
