import { apiGet } from "/js/api.js";
import { createElement, showError } from "/js/render.js";

const feedback = document.querySelector("#feedback");
const preview = document.querySelector("#report-preview");
const identifier = new URLSearchParams(window.location.search).get("id");
let markdown = "";

function section(title, value) {
  const wrapper = createElement("section", { className: "report-section" });
  wrapper.append(createElement("h2", { text: title }), createElement("pre", { text: value }));
  return wrapper;
}

async function loadReport() {
  if (!identifier || !/^\d+$/.test(identifier)) throw new Error("A valid investigation ID is required.");
  const report = await apiGet(`/api/investigations/${identifier}/report`);
  document.querySelector("#report-title").textContent = report.target;
  preview.append(
    section("Summary", `Type: ${report.target_type}\nTimestamp: ${report.timestamp}\nStatus: ${report.status}`),
    section("Risk", report.risk ? `Score: ${report.risk.score}/100\nVerdict: ${report.risk.verdict}` : "Not scored"),
    section("Defensive Recommendations", report.recommendations.map((item) => `• ${item}`).join("\n")),
    section("Stored Analysis", JSON.stringify(report.analysis, null, 2)),
    section("Limitations", report.disclaimer),
  );
  const response = await fetch(`/api/investigations/${identifier}/report?format=md`);
  markdown = await response.text();
}

document.querySelector("#copy-report").addEventListener("click", () => navigator.clipboard.writeText(markdown));
document.querySelector("#download-report").addEventListener("click", () => {
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([markdown], { type: "text/markdown" }));
  link.download = `investigation-${identifier}.md`;
  link.click();
  URL.revokeObjectURL(link.href);
});
document.querySelector("#print-report").addEventListener("click", () => window.open(`/api/investigations/${identifier}/report?format=html`, "_blank", "noopener"));

loadReport().catch((error) => showError(feedback, error.message));
