import { apiPost, setLoading } from "/js/api.js";
import { clearElement, createReportButton, createResultCard, showError } from "/js/render.js";

const form = document.querySelector("#subnet-form");
const feedback = document.querySelector("#feedback");
const results = document.querySelector("#results");
const submitButton = form.querySelector("button[type='submit']");

function renderSubnet(data) {
  clearElement(results);
  results.append(
    createResultCard(
      "Calculated Network",
      [
        ["Input address", data.ip_address],
        ["IP version", `IPv${data.version}`],
        ["CIDR", data.cidr],
        ["Prefix length", `/${data.prefix_length}`],
        ["Network ID", data.network],
        ["Subnet mask", data.subnet_mask],
        ["Wildcard mask", data.wildcard_mask],
        ["First host", data.first_host],
        ["Last host", data.last_host],
        ["Broadcast", data.broadcast],
        ["Total addresses", Number(data.total_addresses).toLocaleString("en-US")],
        ["Usable hosts", Number(data.usable_hosts).toLocaleString("en-US")],
      ],
      {
        wide: true,
        copyValues: true,
        badges: [
          { label: `IPv${data.version}` },
          ...(data.assumed_prefix ? [{ label: "Host prefix assumed", muted: true }] : []),
        ],
      },
    ),
  );
  results.append(createReportButton(data.investigation_id));
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearElement(feedback);
  clearElement(results);
  setLoading(submitButton, true, "Calculating…");

  try {
    const formData = new FormData(form);
    const data = await apiPost("/api/subnet/calculate", {
      ip_cidr: formData.get("ip_cidr"),
    });
    renderSubnet(data);
  } catch (error) {
    showError(feedback, error.message);
  } finally {
    setLoading(submitButton, false);
  }
});
