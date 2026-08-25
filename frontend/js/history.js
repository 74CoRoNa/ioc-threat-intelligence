import { apiDelete, apiGet, setLoading } from "/js/api.js";
import { clearElement, createElement, createVerdictChip, showError } from "/js/render.js";

const filters = document.querySelector("#history-filters");
const feedback = document.querySelector("#feedback");
const rows = document.querySelector("#history-rows");
const count = document.querySelector("#history-count");
const pagination = document.querySelector("#pagination");
const detailPanel = document.querySelector("#investigation-detail");
const detailJSON = document.querySelector("#detail-json");
const filterButton = filters.querySelector("button[type='submit']");
let currentPage = 1;

function queryString(page) {
  const values = new FormData(filters);
  const params = new URLSearchParams({ page: String(page), page_size: "20" });
  for (const [key, value] of values.entries()) {
    if (value) {
      params.set(key, value);
    }
  }
  return params.toString();
}

async function openInvestigation(id) {
  const detail = await apiGet(`/api/investigations/${id}`);
  detailJSON.textContent = JSON.stringify(detail, null, 2);
  const existing = detailPanel.querySelector(".report-button");
  if (existing) existing.remove();
  const reportLink = createElement("a", { className: "report-button", text: "Generate Report" });
  reportLink.href = `/report.html?id=${encodeURIComponent(id)}`;
  detailPanel.append(reportLink);
  detailPanel.hidden = false;
  detailPanel.scrollIntoView({ behavior: "smooth", block: "start" });
}

function createActionButton(label, className, handler) {
  const button = createElement("button", { className, text: label });
  button.type = "button";
  button.addEventListener("click", handler);
  return button;
}

function renderRows(items) {
  clearElement(rows);
  if (!items.length) {
    const row = createElement("tr");
    const cell = createElement("td", {
      className: "empty-state",
      text: "No investigations match these filters.",
    });
    cell.colSpan = 6;
    row.append(cell);
    rows.append(row);
    return;
  }

  for (const item of items) {
    const row = createElement("tr");
    row.append(
      createElement("td", { text: item.target }),
      createElement("td", { text: item.target_type.toUpperCase() }),
      createElement("td", { text: new Date(item.created_at).toLocaleString() }),
    );
    const riskCell = createElement("td");
    riskCell.append(createVerdictChip(item.verdict));
    row.append(riskCell, createElement("td", { text: item.status }));

    const actions = createElement("td", { className: "table-actions" });
    actions.append(
      createActionButton("Open", "copy-button", async () => {
        try {
          await openInvestigation(item.id);
        } catch (error) {
          showError(feedback, error.message);
        }
      }),
      createActionButton("Delete", "copy-button danger-button", async () => {
        if (!window.confirm(`Delete the stored investigation for ${item.target}?`)) {
          return;
        }
        try {
          await apiDelete(`/api/investigations/${item.id}`);
          await loadHistory(currentPage);
        } catch (error) {
          showError(feedback, error.message);
        }
      }),
    );
    row.append(actions);
    rows.append(row);
  }
}

function renderPagination(data) {
  clearElement(pagination);
  const previous = createActionButton("Previous", "secondary-button", () => {
    loadHistory(currentPage - 1);
  });
  previous.disabled = data.page <= 1;
  const next = createActionButton("Next", "secondary-button", () => {
    loadHistory(currentPage + 1);
  });
  next.disabled = data.page >= data.total_pages;
  pagination.append(
    previous,
    createElement("span", {
      text: data.total_pages ? `Page ${data.page} of ${data.total_pages}` : "Page 0 of 0",
    }),
    next,
  );
}

async function loadHistory(page = 1) {
  clearElement(feedback);
  const data = await apiGet(`/api/investigations?${queryString(page)}`);
  currentPage = data.page;
  count.textContent = `${data.total.toLocaleString()} total`;
  renderRows(data.items);
  renderPagination(data);
}

filters.addEventListener("submit", async (event) => {
  event.preventDefault();
  setLoading(filterButton, true, "Loading…");
  try {
    await loadHistory(1);
  } catch (error) {
    showError(feedback, error.message);
  } finally {
    setLoading(filterButton, false);
  }
});

document.querySelector("#close-detail").addEventListener("click", () => {
  detailPanel.hidden = true;
});

loadHistory().catch((error) => showError(feedback, error.message));
