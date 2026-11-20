"use strict";
const TOKEN = "__NOWAY_TOKEN__";
const $ = (id) => document.getElementById(id);
const num = (id) => Number($(id).value);
const lines = (id) =>
  $(id)
    .value.split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
const numberKeys = [
  "workers",
  "rate",
  "timeout",
  "retries",
  "max_hosts",
  "max_related",
  "max_depth",
  "max_pages",
  "source_pages",
];
const boolKeys = [
  "ct",
  "commoncrawl",
  "wordlist",
  "related",
  "asn",
  "verify_tls",
  "allow_private",
  "probe_related",
];
let jobs = [],
  active = null,
  selected = null,
  offset = 0,
  total = 0,
  details = null,
  loading = false,
  noticeTimer;
function notice(text, error = false) {
  clearTimeout(noticeTimer);
  $("notice").textContent = text;
  $("notice").classList.toggle("error", error);
  $("notice").hidden = false;
  noticeTimer = setTimeout(() => ($("notice").hidden = true), 10000);
}
async function api(path, data, method) {
  const options = {
    method: method || (data === undefined ? "GET" : "POST"),
    headers: { "X-Noway-Token": TOKEN },
  };
  if (data !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(data);
  }
  const response = await fetch(path, options);
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Request failed");
  return result;
}
function safe(action) {
  return async (event) => {
    try {
      await action(event);
    } catch (error) {
      notice(error.message, true);
    }
  };
}
function config() {
  const result = {
    roots: lines("roots"),
    seeds: lines("seeds"),
    custom_words: lines("custom_words"),
    dns_servers: lines("dns_servers"),
    mode: $("mode").value,
  };
  for (const key of numberKeys) result[key] = num(key);
  for (const key of boolKeys) result[key] = $(key).checked;
  return result;
}
function fillConfig(value) {
  for (const key of ["roots", "seeds", "custom_words", "dns_servers"])
    $(key).value = (value[key] || []).join("\n");
  for (const key of numberKeys)
    if (value[key] !== undefined) $(key).value = value[key];
  for (const key of boolKeys)
    if (value[key] !== undefined) $(key).checked = value[key];
  $("mode").value = value.mode || "verify";
  $("preset").value = "custom";
  saveDraft();
}
function saveDraft() {
  try {
    const value = JSON.stringify(config());
    if (value.length < 1500000)
      localStorage.setItem("noway-finder-draft", value);
  } catch (_) {}
}
function tab(name) {
  if (!["dashboard", "finder", "results", "history", "settings"].includes(name))
    name = "dashboard";
  document
    .querySelectorAll(".view")
    .forEach((view) => (view.hidden = view.id !== name));
  document
    .querySelectorAll("nav button")
    .forEach((button) =>
      button.classList.toggle("active", button.dataset.tab === name),
    );
  location.hash = name;
  if (name === "results")
    loadResults().catch((error) => notice(error.message, true));
}
document
  .querySelectorAll("[data-tab]")
  .forEach((button) =>
    button.addEventListener("click", () => tab(button.dataset.tab)),
  );
window.addEventListener("hashchange", () => tab(location.hash.slice(1)));
function selectOptions(element, items, value) {
  const current = value === undefined ? element.value : value;
  element.replaceChildren();
  for (const [key, label] of items) {
    const option = document.createElement("option");
    option.value = key;
    option.textContent = label;
    element.append(option);
  }
  if (items.some((item) => String(item[0]) === String(current)))
    element.value = current;
}
function button(text, action, kind = "") {
  const result = document.createElement("button");
  result.textContent = text;
  result.className = kind;
  result.addEventListener("click", safe(action));
  return result;
}
function openJob(id) {
  selected = id;
  offset = 0;
  $("result-job").value = String(id);
  tab("results");
}
async function jobAction(id, action) {
  await api(`/api/jobs/${id}/${action}`, {});
  await refresh();
}
function renderJobs() {
  for (const [container, list] of [
    ["recent", jobs.slice(0, 5)],
    ["history-list", jobs],
  ]) {
    const target = $(container);
    target.replaceChildren();
    if (!list.length) {
      const p = document.createElement("p");
      p.textContent = "No jobs yet. Build a Finder job to begin.";
      target.append(p);
    }
    for (const job of list) {
      const row = document.createElement("div");
      row.className = "job";
      const left = document.createElement("div");
      const title = document.createElement("strong");
      title.textContent = `#${job.id} · ${job.config.roots.join(", ")}`;
      const info = document.createElement("p");
      info.textContent = `${job.state.toUpperCase()} · ${job.checked.toLocaleString()} checked / ${job.total.toLocaleString()} hosts · ${job.cdn.toLocaleString()} CDN`;
      left.append(title, info);
      const actions = document.createElement("div");
      actions.className = "button-row";
      actions.append(button("Evidence", () => openJob(job.id)));
      if (container === "history-list") {
        if (!["completed", "running"].includes(job.state))
          actions.append(
            button(job.state === "queued" ? "Start" : "Resume", () =>
              jobAction(job.id, "start"),
            ),
          );
        actions.append(
          button("Reuse settings", () => {
            fillConfig(job.config);
            tab("finder");
            notice("Settings loaded. Review and start a new job.");
          }),
        );
        actions.append(
          button(
            "Delete",
            async () => {
              if (confirm(`Delete saved job #${job.id} and its evidence?`)) {
                await api(`/api/jobs/${job.id}`, undefined, "DELETE");
                if (selected === job.id) selected = null;
                await refresh();
              }
            },
            "danger",
          ),
        );
      }
      row.append(left, actions);
      target.append(row);
    }
  }
}
async function refresh() {
  if (loading) return;
  loading = true;
  try {
    const data = await api("/api/status");
    jobs = data.jobs;
    active = data.active_job;
    const running = jobs.find((job) => job.id === active);
    $("state").textContent = running ? running.state.toUpperCase() : "READY";
    for (const [id, key] of [
      ["stat-hosts", "total"],
      ["stat-cdn", "cdn"],
      ["stat-related", "related"],
    ])
      $(id).textContent = jobs
        .reduce((sum, job) => sum + job[key], 0)
        .toLocaleString();
    $("stat-jobs").textContent = jobs.length.toLocaleString();
    const current = running || jobs[0];
    $("live-text").textContent = current
      ? `Job #${current.id} · ${current.state} · ${current.checked.toLocaleString()} / ${current.total.toLocaleString()} checked · ${current.config.roots.join(", ")}`
      : "Your workspace is ready.";
    $("warnings").textContent = current ? current.warnings.join(" · ") : "";
    $("progress").value =
      current && current.total ? current.checked / current.total : 0;
    $("pause").disabled = !running;
    $("stop").disabled = !running;
    $("start").textContent = running ? "Add to queue" : "Start Finder";
    const options = jobs.map((job) => [
      String(job.id),
      `#${job.id} · ${job.config.roots.join(", ")} · ${job.state}`,
    ]);
    if (selected === null && jobs.length) selected = jobs[0].id;
    if (selected !== null && !jobs.some((job) => job.id === selected))
      selected = jobs[0]?.id ?? null;
    selectOptions($("result-job"), options, selected);
    selectOptions($("compare-first"), options);
    selectOptions($("compare-second"), options);
    renderJobs();
    if (!$("results").hidden && selected === active) await loadResults();
  } finally {
    loading = false;
  }
}
function query() {
  const params = new URLSearchParams();
  for (const [key, id] of [
    ["q", "query"],
    ["provider", "provider"],
    ["scope", "scope"],
    ["confidence", "confidence"],
    ["family", "family"],
    ["status", "http-status"],
  ])
    if ($(id).value) params.set(key, $(id).value);
  for (const key of ["alive", "cdn"]) if ($(key).checked) params.set(key, "1");
  return params;
}
let resultSequence = 0;
async function loadResults() {
  const sequence = ++resultSequence;
  if (selected === null) {
    $("result-rows").replaceChildren();
    $("result-count").textContent = "No saved jobs";
    return;
  }
  const params = query();
  params.set("offset", offset);
  params.set("limit", 100);
  const result = await api(`/api/jobs/${selected}/results?${params}`);
  if (sequence !== resultSequence) return;
  total = result.total;
  const body = $("result-rows");
  body.replaceChildren();
  for (const finding of result.rows) {
    const tr = document.createElement("tr");
    for (const text of [
      finding.hostname,
      `${finding.provider} · ${finding.confidence}`,
      finding.scope === "in_scope" ? "Under root" : "Related",
      finding.status ?? finding.record_state,
      finding.ips.join(", ") || "—",
    ]) {
      const td = document.createElement("td");
      td.textContent = text;
      tr.append(td);
    }
    const td = document.createElement("td");
    td.append(
      button("Inspect", () => {
        details = finding;
        $("detail-text").textContent = JSON.stringify(finding, null, 2);
        $("details").showModal();
      }),
    );
    tr.append(td);
    body.append(tr);
  }
  if (!result.rows.length) {
    const tr = document.createElement("tr"),
      td = document.createElement("td");
    td.colSpan = 6;
    td.textContent = "No findings match the current filters.";
    tr.append(td);
    body.append(tr);
  }
  $("result-count").textContent =
    `${total ? offset + 1 : 0}–${offset + result.rows.length} of ${total.toLocaleString()} matching records`;
  $("previous").disabled = offset === 0;
  $("next").disabled = offset + 100 >= total;
}
async function profiles() {
  const data = await api("/api/profiles");
  selectOptions($("profile"), [
    ["", "Choose a profile"],
    ...Object.keys(data).map((name) => [name, name]),
  ]);
  return data;
}
function review() {
  if (!$("finder-form").reportValidity()) return;
  saveDraft();
  const value = config();
  $("review-text").textContent = JSON.stringify(value, null, 2);
  $("review").showModal();
}
$("finder-form").addEventListener("submit", (event) => {
  event.preventDefault();
  review();
});
$("preview").addEventListener("click", review);
$("review-close").addEventListener("click", () => $("review").close());
$("detail-close").addEventListener("click", () => $("details").close());
$("confirm-start").addEventListener(
  "click",
  safe(async () => {
    const btn = $("confirm-start");
    btn.disabled = true;
    try {
      const result = await api("/api/jobs", config());
      $("review").close();
      selected = result.job;
      if (active === null) {
        await jobAction(result.job, "start");
        notice(`Finder job #${result.job} started.`);
      } else notice(`Job #${result.job} added to queue.`);
      await refresh();
      tab("dashboard");
    } finally {
      btn.disabled = false;
    }
  }),
);
$("pause").addEventListener(
  "click",
  safe(() => jobAction(active, "pause")),
);
$("stop").addEventListener(
  "click",
  safe(() => jobAction(active, "stop")),
);
$("clear-targets").addEventListener("click", () => {
  $("roots").value = "";
  $("seeds").value = "";
  $("import-summary").textContent = "No imported hosts.";
  saveDraft();
});
$("import-file").addEventListener(
  "change",
  safe(async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    if (file.size > 20 * 1024 * 1024) throw new Error("Import exceeds 20 MiB");
    const result = await api("/api/import", { text: await file.text() });
    const field = $($("import-mode").value);
    const merged = new Set([
      ...field.value.split(/\r?\n/).filter(Boolean),
      ...result.hosts,
    ]);
    field.value = [...merged].join("\n");
    $("import-summary").textContent =
      `${result.hosts.length.toLocaleString()} valid unique hosts imported · ${result.invalid_count} invalid values skipped`;
    saveDraft();
    event.target.value = "";
  }),
);
$("preset").addEventListener("change", () => {
  const values = { eco: [8, 10], balanced: [32, 30], fast: [64, 100] }[
    $("preset").value
  ];
  if (values) {
    $("workers").value = values[0];
    $("rate").value = values[1];
  }
  saveDraft();
});
$("mode").addEventListener("change", () => {
  if ($("mode").value === "discover") $("wordlist").checked = false;
  saveDraft();
});
$("finder-form").addEventListener("input", saveDraft);
$("finder-form").addEventListener("change", saveDraft);
$("save-profile").addEventListener(
  "click",
  safe(async () => {
    const name = prompt("Profile name");
    if (!name) return;
    await api("/api/profiles", { name, config: config() });
    await profiles();
    notice("Profile saved.");
  }),
);
$("load-profile").addEventListener(
  "click",
  safe(async () => {
    const values = await profiles();
    const value = values[$("profile").value];
    if (value) fillConfig(value);
  }),
);
$("result-job").addEventListener(
  "change",
  safe(async () => {
    selected = Number($("result-job").value);
    offset = 0;
    await loadResults();
  }),
);
$("apply-filters").addEventListener(
  "click",
  safe(async () => {
    offset = 0;
    await loadResults();
  }),
);
$("reset-filters").addEventListener(
  "click",
  safe(async () => {
    for (const id of [
      "query",
      "provider",
      "scope",
      "confidence",
      "http-status",
    ])
      $(id).value = "";
    $("family").value = "0";
    $("alive").checked = false;
    $("cdn").checked = false;
    offset = 0;
    await loadResults();
  }),
);
$("query").addEventListener(
  "keydown",
  safe(async (event) => {
    if (event.key === "Enter") {
      offset = 0;
      await loadResults();
    }
  }),
);
$("previous").addEventListener(
  "click",
  safe(async () => {
    offset = Math.max(0, offset - 100);
    await loadResults();
  }),
);
$("next").addEventListener(
  "click",
  safe(async () => {
    if (offset + 100 < total) {
      offset += 100;
      await loadResults();
    }
  }),
);
function download(format) {
  if (selected === null) {
    notice("Choose a saved job first.", true);
    return;
  }
  const params = query();
  params.set("format", format);
  params.set("txt_field", $("txt-field").value);
  const link = document.createElement("a");
  link.href = `/api/jobs/${selected}/export?${params}`;
  link.download = "";
  document.body.append(link);
  link.click();
  link.remove();
}
document
  .querySelectorAll("[data-export]")
  .forEach((btn) =>
    btn.addEventListener("click", () => download(btn.dataset.export)),
  );
$("download-extra").addEventListener("click", () =>
  download($("extra-export").value),
);
$("run-next").addEventListener(
  "click",
  safe(async () => {
    const next = [...jobs].reverse().find((job) => job.state === "queued");
    if (!next) throw new Error("No queued jobs");
    await api("/api/queue/start", {});
    await refresh();
  }),
);
$("compare").addEventListener(
  "click",
  safe(async () => {
    const params = new URLSearchParams({
      first: $("compare-first").value,
      second: $("compare-second").value,
    });
    $("comparison").textContent = JSON.stringify(
      await api(`/api/compare?${params}`),
      null,
      2,
    );
  }),
);
$("copy-finding").addEventListener(
  "click",
  safe(async () => {
    await navigator.clipboard.writeText(JSON.stringify(details, null, 2));
    notice("Finding copied.");
  }),
);
$("theme").addEventListener("change", () => {
  document.body.classList.toggle("light", $("theme").value === "light");
  localStorage.setItem("noway-finder-theme", $("theme").value);
});
$("update-data").addEventListener(
  "click",
  safe(async () => {
    const btn = $("update-data");
    btn.disabled = true;
    $("update-status").textContent = "Refreshing official sources…";
    try {
      const result = await api("/api/update-data", {});
      $("update-status").textContent = Object.entries(result)
        .map(([key, value]) => `${key}: ${value} prefixes`)
        .join(" · ");
    } finally {
      btn.disabled = false;
    }
  }),
);
async function initialize() {
  try {
    const saved = localStorage.getItem("noway-finder-draft");
    if (saved) fillConfig(JSON.parse(saved));
    const theme = localStorage.getItem("noway-finder-theme") || "dark";
    $("theme").value = theme;
    document.body.classList.toggle("light", theme === "light");
  } catch (_) {}
  await profiles();
  await refresh();
  tab(location.hash.slice(1) || "dashboard");
  setInterval(
    () => refresh().catch((error) => notice(error.message, true)),
    2500,
  );
}
initialize().catch((error) => notice(error.message, true));
