const pathInput = document.getElementById("path");
const scanBtn = document.getElementById("scanBtn");
const progressBar = document.getElementById("progressBar");
const progressLabel = document.getElementById("progressLabel");
const progressCounts = document.getElementById("progressCounts");
const currentPath = document.getElementById("currentPath");
const findingsEl = document.getElementById("findings");
const summaryEl = document.getElementById("summary");
const frameworksEl = document.getElementById("frameworks");
const healthEl = document.getElementById("health");
const targetGrid = document.getElementById("targetGrid");
const focusTargetsEl = document.getElementById("focusTargets");

let targetCatalog = [];

function setProgress(pct, label, countsText, pathText) {
    progressBar.style.setProperty("--pct", `${Math.min(100, Math.max(0, pct))}%`);
    progressLabel.textContent = label;
    progressCounts.textContent = countsText ?? "";
    currentPath.textContent = pathText ?? "";
}

function severityClass(sev) {
    const s = (sev || "info").toLowerCase();
    return `sev sev-${s}`;
}

function renderFinding(f) {
    const card = document.createElement("article");
    card.className = "card";
    const header = document.createElement("div");
    header.className = "card-header";
    const badge = document.createElement("span");
    badge.className = severityClass(f.severity);
    badge.textContent = f.severity;
    const title = document.createElement("h3");
    title.className = "card-title";
    title.textContent = f.title;
    header.appendChild(badge);
    header.appendChild(title);
    card.appendChild(header);

    const meta = document.createElement("p");
    meta.className = "meta";
    const loc = f.line != null ? `${f.path}:${f.line}` : f.path;
    const fw = f.framework ? ` · ${f.framework}` : "";
    const rule = f.rule_id ? ` · ${f.rule_id}` : "";
    const tids = f.target_ids?.length ? ` · targets: ${f.target_ids.join(", ")}` : "";
    meta.textContent = `${loc}${fw}${rule}${tids}`;
    card.appendChild(meta);

    if (f.evidence) {
        const ev = document.createElement("pre");
        ev.className = "evidence";
        ev.textContent = f.evidence;
        card.appendChild(ev);
    }

    const rec = document.createElement("p");
    rec.className = "recommendation";
    rec.textContent = f.recommendation;
    card.appendChild(rec);

    return card;
}

function selectedTargets() {
    return [...targetGrid.querySelectorAll('input[type="checkbox"]:checked')].map((el) => el.value);
}

function renderTargetGrid() {
    targetGrid.innerHTML = "";
    const byCat = new Map();
    for (const t of targetCatalog) {
        const c = t.category || "Other";
        if (!byCat.has(c)) byCat.set(c, []);
        byCat.get(c).push(t);
    }
    for (const [cat, items] of byCat) {
        const sub = document.createElement("div");
        sub.className = "target-category";
        const h = document.createElement("div");
        h.className = "target-cat-label";
        h.textContent = cat;
        h.style.cssText = "grid-column: 1/-1;font-size:0.72rem;text-transform:uppercase;letter-spacing:0.06em;color:#7d8ca3;margin:0.35rem 0 0.15rem";
        sub.appendChild(h);
        for (const t of items) {
            const label = document.createElement("label");
            label.className = "target-item";
            const cb = document.createElement("input");
            cb.type = "checkbox";
            cb.value = t.id;
            const span = document.createElement("span");
            span.innerHTML = `<span class="target-label">${escapeHtml(t.label)}</span><span class="target-desc">${escapeHtml(t.description)}</span>`;
            label.appendChild(cb);
            label.appendChild(span);
            sub.appendChild(label);
        }
        targetGrid.appendChild(sub);
    }
}

function escapeHtml(s) {
    return String(s)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

function renderFrameworkChips(evt) {
    frameworksEl.innerHTML = "";
    const detected = new Set(evt.detected_frameworks || evt.frameworks || []);
    const declared = new Set(evt.declared_targets || []);
    const effective = new Set(evt.effective_targets || [...detected, ...declared]);

    const addChip = (id, cls) => {
        const meta = targetCatalog.find((t) => t.id === id);
        const chip = document.createElement("span");
        chip.className = `chip ${cls}`;
        chip.textContent = meta ? meta.label : id;
        chip.title = id;
        frameworksEl.appendChild(chip);
    };

    for (const id of [...effective].sort()) {
        let cls = "effective";
        if (detected.has(id) && !declared.has(id)) cls = "detected";
        else if (!detected.has(id) && declared.has(id)) cls = "declared";
        addChip(id, cls);
    }

    if (effective.size === 0) {
        const chip = document.createElement("span");
        chip.className = "chip";
        chip.textContent = "No stacks tagged";
        frameworksEl.appendChild(chip);
    }
}

async function loadHealth() {
    try {
        const res = await fetch("/api/health");
        const data = await res.json();
        healthEl.textContent = `Backend OK · scanner root: ${data.scannerRoot}`;
    } catch {
        healthEl.textContent = "Backend unreachable — start the Java server (port 8080).";
    }
}

async function loadTargets() {
    try {
        const res = await fetch("/api/targets");
        targetCatalog = await res.json();
        renderTargetGrid();
    } catch {
        targetGrid.innerHTML = '<p class="error">Could not load target catalog.</p>';
    }
}

async function startScan() {
    const path = pathInput.value.trim();
    if (!path) {
        summaryEl.innerHTML = '<span class="error">Enter a project folder path.</span>';
        return;
    }

    scanBtn.disabled = true;
    findingsEl.innerHTML = "";
    summaryEl.textContent = "";
    frameworksEl.innerHTML = "";
    setProgress(0, "Starting…", "", "");

    const findings = [];
    const targets = selectedTargets();
    const focusTargets = focusTargetsEl.checked;

    try {
        const res = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ path, targets, focusTargets }),
        });

        if (!res.ok || !res.body) {
            summaryEl.innerHTML = `<span class="error">Scan request failed (${res.status})</span>`;
            return;
        }

        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            let idx;
            while ((idx = buffer.indexOf("\n")) >= 0) {
                const line = buffer.slice(0, idx).trim();
                buffer = buffer.slice(idx + 1);
                if (!line) continue;
                let evt;
                try {
                    evt = JSON.parse(line);
                } catch {
                    continue;
                }
                if (evt.type === "started") {
                    setProgress(0, "Scanning…", "", evt.path || "");
                    const unk = evt.unknown_declared?.length
                        ? ` · unknown IDs: ${evt.unknown_declared.join(", ")}`
                        : "";
                    if (evt.focus) {
                        currentPath.textContent = (currentPath.textContent || "") + " · focus mode" + unk;
                    } else if (unk) {
                        currentPath.textContent = (evt.path || "") + unk;
                    }
                } else if (evt.type === "progress") {
                    const pct = typeof evt.percent === "number" ? evt.percent : 0;
                    const doneC = evt.done ?? 0;
                    const total = evt.total ?? 0;
                    setProgress(pct, "Scanning…", `${doneC} / ${total} files`, evt.current_path || "");
                } else if (evt.type === "finding" && evt.finding) {
                    findings.push(evt.finding);
                    findingsEl.appendChild(renderFinding(evt.finding));
                    findingsEl.scrollTop = findingsEl.scrollHeight;
                } else if (evt.type === "done") {
                    const s = evt.summary || {};
                    const by = s.by_severity || {};
                    const parts = Object.keys(by).map((k) => `${k}: ${by[k]}`);
                    let extra = "";
                    if (evt.unknown_declared?.length) {
                        extra += ` Unknown target IDs (ignored): ${evt.unknown_declared.join(", ")}.`;
                    }
                    if (evt.focus) {
                        extra += " Focus mode: only universal + selected stack-tagged rules.";
                    }
                    summaryEl.textContent = `Finished · ${s.total ?? findings.length} finding(s)${parts.length ? " (" + parts.join(", ") + ")" : ""}.${extra}`;
                    renderFrameworkChips(evt);
                    setProgress(100, "Complete", "", "");
                } else if (evt.type === "error") {
                    summaryEl.innerHTML = `<span class="error">${evt.message || "Error"}</span>`;
                }
            }
        }

        if (findings.length === 0 && !summaryEl.textContent) {
            findingsEl.innerHTML = '<p class="empty">No issues reported for this path with the current rules.</p>';
        }
    } catch (e) {
        summaryEl.innerHTML = `<span class="error">${e.message || "Scan failed"}</span>`;
    } finally {
        scanBtn.disabled = false;
    }
}

scanBtn.addEventListener("click", startScan);
pathInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") startScan();
});

loadHealth();
loadTargets();
