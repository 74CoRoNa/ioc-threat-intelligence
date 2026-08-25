import { apiGet } from "/js/api.js";
import { createElement, createVerdictChip, showError } from "/js/render.js";

const feedback = document.querySelector("#feedback");
const SVG_NS = "http://www.w3.org/2000/svg";

function svg(tag, attributes = {}) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [name, value] of Object.entries(attributes)) {
    node.setAttribute(name, String(value));
  }
  return node;
}

function renderTiles(summary) {
  const tiles = document.querySelector("#stat-tiles");
  const rows = [
    ["Total", summary.total],
    ["Low", summary.low],
    ["Medium", summary.medium],
    ["High", summary.high],
    ["Critical", summary.critical],
  ];
  for (const [label, value] of rows) {
    const tile = createElement("article", { className: `stat-tile stat-tile--${label.toLowerCase()}` });
    tile.append(
      createElement("span", { text: label }),
      createElement("strong", { text: value.toLocaleString() }),
    );
    tiles.append(tile);
  }
}

function renderBars(buckets) {
  const container = document.querySelector("#risk-bars");
  const maximum = Math.max(1, ...Object.values(buckets));
  for (const [label, value] of Object.entries(buckets)) {
    const row = createElement("div", { className: "risk-bar-row" });
    const track = createElement("div", { className: "risk-bar-track" });
    const fill = createElement("span", { className: `risk-bar risk-bar--${label.toLowerCase()}` });
    fill.style.width = `${(value / maximum) * 100}%`;
    if (!value) fill.dataset.zero = "yes";
    track.append(fill);
    row.append(
      createElement("span", { text: label }),
      track,
      createElement("strong", { text: value }),
    );
    container.append(row);
  }
}

function shortDate(iso) {
  return new Date(`${iso}T00:00:00`).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
  });
}

/**
 * Seven-day volume as a single-series line chart: hairline grid, one accent
 * hue, direct labels only on the peak and the latest point, and a hover layer
 * over targets far larger than the markers themselves.
 */
function renderTrend(series) {
  const chart = document.querySelector("#trend-chart");
  const LEFT = 36;
  const RIGHT = 14;
  const TOP = 16;
  const BOTTOM = 30;
  const WIDTH = 640;
  const HEIGHT = 200;
  const plotWidth = WIDTH - LEFT - RIGHT;
  const plotHeight = HEIGHT - TOP - BOTTOM;

  chart.setAttribute("viewBox", `0 0 ${WIDTH} ${HEIGHT}`);
  chart.replaceChildren();

  const peak = Math.max(...series.map((item) => item.count));
  let step = Math.max(1, Math.ceil(peak / 3));
  // Leave headroom so the peak marker and its label clear the top gridline.
  if (peak > 0 && peak / (step * 3) > 0.9) step += Math.max(1, Math.round(step * 0.2));
  const maximum = Math.max(step * 3, 3);

  const x = (index) => LEFT + (plotWidth * index) / Math.max(1, series.length - 1);
  const y = (count) => TOP + plotHeight * (1 - count / maximum);

  for (let value = 0; value <= maximum; value += step) {
    chart.append(svg("line", { class: "grid", x1: LEFT, x2: WIDTH - RIGHT, y1: y(value), y2: y(value) }));
    const tick = svg("text", { class: "tick", x: LEFT - 8, y: y(value) + 3.5, "text-anchor": "end" });
    tick.textContent = value;
    chart.append(tick);
  }
  chart.append(svg("line", { class: "axis", x1: LEFT, x2: WIDTH - RIGHT, y1: y(0), y2: y(0) }));

  chart.append(svg("polyline", {
    class: "line",
    points: series.map((item, index) => `${x(index)},${y(item.count)}`).join(" "),
  }));

  const labelled = new Set([series.findIndex((item) => item.count === peak), series.length - 1]);
  series.forEach((item, index) => {
    const label = svg("text", { class: "tick", x: x(index), y: HEIGHT - 10, "text-anchor": "middle" });
    label.textContent = shortDate(item.date);
    chart.append(label);

    // A generous invisible target keeps the 8px marker from being a pinpoint.
    const hit = svg("rect", {
      class: "hit",
      x: x(index) - plotWidth / (series.length * 2),
      y: TOP,
      width: plotWidth / series.length,
      height: plotHeight,
      tabindex: "0",
    });
    const tooltip = svg("title");
    tooltip.textContent = `${shortDate(item.date)}: ${item.count} investigation(s)`;
    hit.append(tooltip);
    chart.append(hit, svg("circle", { class: "dot", cx: x(index), cy: y(item.count), r: 4 }));

    // Direct-label the peak and the latest point only, flipping the label
    // below its marker when there is no room above it.
    if (peak > 0 && labelled.has(index)) {
      const above = y(item.count) - 10;
      const value = svg("text", {
        class: "value",
        x: x(index),
        y: above < 11 ? y(item.count) + 17 : above,
        "text-anchor": index === series.length - 1 ? "end" : "middle",
      });
      value.textContent = item.count;
      chart.append(value);
    }
  });

  renderTrendTable(series);
}

/** The table-view twin, so no value is reachable only by hovering. */
function renderTrendTable(series) {
  const target = document.querySelector("#trend-table");
  if (!target) return;
  const table = createElement("table");
  const thead = createElement("thead");
  const tbody = createElement("tbody");
  const head = createElement("tr");
  const body = createElement("tr");
  for (const item of series) {
    head.append(createElement("th", { text: shortDate(item.date) }));
    body.append(createElement("td", { text: item.count }));
  }
  thead.append(head);
  tbody.append(body);
  table.append(thead, tbody);
  target.append(table);
}

function renderList(containerId, items, formatter, emptyMessage) {
  const container = document.querySelector(containerId);
  if (!items.length) {
    container.append(createElement("p", { className: "empty-state", text: emptyMessage }));
    return;
  }
  const list = createElement("div", { className: "dashboard-list" });
  items.forEach((item) => list.append(formatter(item)));
  container.append(list);
}

async function load() {
  const [summary, recent, top, distribution] = await Promise.all([
    apiGet("/api/stats/summary"),
    apiGet("/api/stats/recent"),
    apiGet("/api/stats/top-iocs"),
    apiGet("/api/stats/distribution"),
  ]);

  renderTiles(summary);
  renderBars(distribution.risk_buckets);
  renderTrend(distribution.time_series);

  renderList(
    "#recent-list",
    recent,
    (item) => {
      const row = createElement("a", { className: "dashboard-row" });
      row.href = "/history.html";
      row.append(
        createElement("span", { text: item.target }),
        createVerdictChip(item.verdict),
      );
      return row;
    },
    "No investigations yet — analyze an indicator to begin.",
  );

  renderList(
    "#top-iocs",
    top,
    (item) => {
      const row = createElement("div", { className: "dashboard-row" });
      row.append(
        createElement("span", { text: item.value }),
        createElement("span", { className: "chip chip--plain", text: `${item.occurrences}×` }),
      );
      return row;
    },
    "No extracted indicators yet.",
  );
}

load().catch((error) => showError(feedback, error.message));
