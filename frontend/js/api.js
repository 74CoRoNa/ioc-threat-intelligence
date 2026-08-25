function messageFromError(payload, fallback) {
  return payload?.error?.message || fallback;
}

async function request(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      Accept: "application/json",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...options.headers,
    },
  });

  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(messageFromError(payload, `Request failed (${response.status})`));
  }

  return payload;
}

export function apiGet(path) {
  return request(path);
}

export function apiPost(path, body) {
  return request(path, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export function apiDelete(path) {
  return request(path, { method: "DELETE" });
}

export function setLoading(element, isLoading, label = "Loading…") {
  element.disabled = isLoading;
  element.setAttribute("aria-busy", String(isLoading));

  if (isLoading) {
    element.dataset.previousLabel = element.textContent;
    element.textContent = label;
  } else if (element.dataset.previousLabel) {
    element.textContent = element.dataset.previousLabel;
    delete element.dataset.previousLabel;
  }
}
