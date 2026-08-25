import { apiPost, setLoading } from "/js/api.js";
import { clearElement, createBadge, createElement, showError } from "/js/render.js";

const form = document.querySelector("#log-form");
const feedback = document.querySelector("#feedback");
const panel = document.querySelector("#ioc-panel");
const rows = document.querySelector("#ioc-rows");
const count = document.querySelector("#ioc-count");
const progress = document.querySelector("#batch-progress");
const extractButton = form.querySelector("button[type='submit']");
const selectedButton = document.querySelector("#analyze-selected");
const allButton = document.querySelector("#analyze-all");
let indicators = [];

function contextFor(item) {
  const labels = [];
  if (item.private_or_local) labels.push("Private / local");
  if (item.common_benign) labels.push("Common benign");
  return labels.join(" · ") || "—";
}

function renderIndicators() {
  clearElement(rows);
  indicators.forEach((item, index) => {
    const row = createElement("tr");
    const selectCell = createElement("td");
    const checkbox = createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = true;
    checkbox.dataset.index = String(index);
    checkbox.setAttribute("aria-label", `Select ${item.value}`);
    selectCell.append(checkbox);
    const riskCell = createElement("td");
    riskCell.append(createBadge(item.score === undefined ? "Not analyzed" : `${item.score}/100`, item.score === undefined));
    row.append(
      selectCell,
      createElement("td", { text: item.value }),
      createElement("td", { text: item.type.toUpperCase() }),
      createElement("td", { text: item.count }),
      createElement("td", { text: contextFor(item) }),
      riskCell,
      createElement("td", { text: item.analysis_status || "Ready" }),
    );
    rows.append(row);
  });
  count.textContent = `${indicators.length.toLocaleString()} unique IOC${indicators.length === 1 ? "" : "s"}`;
}

async function analyze(indexes) {
  if (!indexes.length) {
    showError(feedback, "Select at least one indicator to analyze.");
    return;
  }
  clearElement(feedback);
  progress.textContent = `Analyzing ${indexes.length} indicator(s)…`;
  selectedButton.disabled = true;
  allButton.disabled = true;
  try {
    const response = await apiPost("/api/analyze/ioc/bulk", {
      iocs: indexes.map((index) => ({
        value: indicators[index].value,
        type: indicators[index].type,
      })),
    });
    response.items.forEach((result, position) => {
      const item = indicators[indexes[position]];
      item.score = result.score;
      item.analysis_status = result.status === "ok" ? "Complete" : result.error;
    });
    indicators.sort((left, right) => (right.score ?? -1) - (left.score ?? -1));
    renderIndicators();
    progress.textContent = `Completed ${response.items.length} analyses · investigation #${response.investigation_id}`;
  } catch (error) {
    showError(feedback, error.message);
    progress.textContent = "Batch analysis did not complete.";
  } finally {
    selectedButton.disabled = false;
    allButton.disabled = false;
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearElement(feedback);
  setLoading(extractButton, true, "Extracting…");
  try {
    const data = await apiPost("/api/analyze/log", {
      text: new FormData(form).get("text"),
    });
    indicators = data.iocs;
    renderIndicators();
    panel.hidden = false;
    progress.textContent = data.message || (data.refanged ? "Defanged indicators were normalized." : "Ready to analyze.");
  } catch (error) {
    showError(feedback, error.message);
  } finally {
    setLoading(extractButton, false);
  }
});

selectedButton.addEventListener("click", () => {
  const indexes = [...rows.querySelectorAll("input[type='checkbox']:checked")]
    .map((checkbox) => Number(checkbox.dataset.index));
  analyze(indexes);
});

allButton.addEventListener("click", () => analyze(indicators.map((_, index) => index)));

