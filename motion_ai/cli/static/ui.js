(() => {
  /* refs */
  const listEl   = document.getElementById("session-list");
  const canvas   = document.getElementById("health-canvas");
  const caption  = document.getElementById("chart-caption");
  const qNowEl   = document.getElementById("queue-now");
  const qPeakEl  = document.getElementById("queue-peak");
  const sbEl     = document.getElementById("standby-flag");
  const actEl    = document.getElementById("active-flag");
  const framesGrid = document.getElementById("frames-grid");
  const frameInfo  = document.getElementById("frame-info");
  const slider   = document.getElementById("frame-slider");
  const prevBtn  = document.getElementById("prev-btn");
  const nextBtn  = document.getElementById("next-btn");
  const gPrevBtn = document.getElementById("group-prev");
  const gNextBtn = document.getElementById("group-next");
  const gLabel   = document.getElementById("group-label");
  const openBtn  = document.getElementById("open-btn");
  const logList  = document.getElementById("log-list");
  const logMeta  = document.getElementById("log-meta");
  const modal    = document.getElementById("img-modal");
  const modalImg = document.getElementById("modal-img");
  const mPrev    = document.getElementById("m-prev");
  const mNext    = document.getElementById("m-next");
  const legendEl = document.getElementById("chart-legend");

  /* series */
  const SERIES = [
    { key: "cpu",  label: "CPU",  color: "#005ff9", unit: "%",  y: "pct",  dash: [] },
    { key: "ram",  label: "RAM",  color: "#00a87e", unit: "%",  y: "pct",  dash: [6,4] },
    { key: "temp", label: "Temp", color: "#ff6a00", unit: "°C", y: "temp", dash: [3,3] },
  ];
  let visible = { cpu: true, ram: true, temp: true };
  let hoverIndex = null;

  /* state */
  let sessions = [];
  let sid = null;
  const seriesCache = new Map();
  let groups = [];
  let gidx = 0;
  let ridx = 0;

  /* init */
  document.addEventListener("DOMContentLoaded", init);
  async function init() {
    await fetchSessions();
    renderSessionList();
    if (sessions.length > 0) { await selectSession(sessions[0].id); } else { clearUI(); }
    wireControls();
    buildLegend();
    wireChartHover();
    updateLegendValues();
    drawChart();
  }

  /* legend */
  function buildLegend() {
    if (!legendEl) return;
    legendEl.innerHTML = "";
    SERIES.forEach(s => {
      const item = document.createElement("div");
      item.className = "legend__item";
      item.dataset.key = s.key;

      const sw = document.createElement("span");
      sw.className = "legend__swatch";
      sw.style.background = s.color;

      const lab = document.createElement("span");
      lab.className = "legend__label";
      lab.textContent = s.label;

      const val = document.createElement("span");
      val.className = "legend__value";
      val.id = `legend-value-${s.key}`;
      val.textContent = "—";

      item.append(sw, lab, val);
      item.onclick = () => {
        visible[s.key] = !visible[s.key];
        item.classList.toggle("is-off", !visible[s.key]);
        drawChart();
        updateLegendValues();
      };
      legendEl.appendChild(item);
    });
  }

  function updateLegendValues(sample) {
    const ser = sid && seriesCache.get(sid);
    const health = ser && Array.isArray(ser.health) ? ser.health : [];
    const h = sample || health[health.length - 1];
    const map = h ? {
      cpu:  Number.isFinite(+h.cpu)  ? `${(+h.cpu).toFixed(1)}%`   : "—",
      ram:  Number.isFinite(+h.ram)  ? `${(+h.ram).toFixed(1)}%`   : "—",
      temp: Number.isFinite(+h.temp) ? `${(+h.temp).toFixed(1)}°C` : "—",
    } : { cpu:"—", ram:"—", temp:"—" };
    SERIES.forEach(s => {
      const el = document.getElementById(`legend-value-${s.key}`);
      if (el) el.textContent = visible[s.key] ? map[s.key] : "—";
    });
  }

  function wireChartHover() {
    if (!canvas) return;
    canvas.addEventListener("mousemove", onCanvasHover);
    canvas.addEventListener("mouseleave", () => { hoverIndex = null; updateLegendValues(); drawChart(); });
  }

  function onCanvasHover(ev) {
    const rect = canvas.getBoundingClientRect();
    const x = ev.clientX - rect.left;
    const W  = canvas.clientWidth || canvas.parentElement.clientWidth || 900;
    const padL = 52, padR = 60, padT = 20, padB = 34;
    const plotW = Math.max(0, W - padL - padR);
    const ser = sid && seriesCache.get(sid);
    const health = ser && Array.isArray(ser.health) ? ser.health : [];
    if (health.length < 2) return;
    const rel = clamp((x - padL) / plotW, 0, 1);
    hoverIndex = Math.round(rel * (health.length - 1));
    updateLegendValues(health[hoverIndex]);
    drawChart();
  }

  /* data */
  async function fetchSessions() {
    try {
      const res = await fetch("/sessions", { headers: { "Accept": "application/json" } });
      if (!res.ok) throw new Error(`GET /sessions failed: ${res.status}`);
      sessions = await res.json();
    } catch (err) {
      console.error(err);
      sessions = [];
    }
  }

  async function fetchSeries(id) {
    if (seriesCache.has(id)) return seriesCache.get(id);
    let data = { health: [], ticks: [] };
    try {
      const res = await fetch(`/sessions/${encodeURIComponent(id)}/series`, { headers: { "Accept": "application/json" } });
      if (res.ok) data = await res.json();
    } catch {}
    seriesCache.set(id, data);
    return data;
  }

  /* sessions */
  function renderSessionList() {
    listEl.innerHTML = "";
    sessions.forEach(s => {
      const li = document.createElement("li");
      li.textContent = s.id;
      li.onclick = () => selectSession(s.id);
      if (s.id === sid) li.classList.add("selected");
      listEl.appendChild(li);
    });
  }

  async function selectSession(id) {
    sid = id;
    [...listEl.children].forEach(li => li.classList.toggle("selected", li.textContent === id));
    const s = current();
    groups = buildGroups(s.frames, s.events);
    gidx = 0;
    ridx = 0;
    renderGroupFrames();
    updateFrameUI();
    updateGroupLabel();
    await fetchSeries(id);
    drawChart();
    updateRuntimeBox();
    renderUnifiedLog();
    updateLegendValues();
  }

  function current() {
    return sessions.find(s => s.id === sid) || { id: "empty", frames: [], events: [] };
  }

  /* alerts */
  function ensureAlertBar() {
    let el = document.getElementById("alert-bar");
    if (!el) {
      el = document.createElement("div");
      el.id = "alert-bar";
      el.className = "alert";
      (document.querySelector(".content") || document.body).prepend(el);
    }
    return el;
  }
  function showError(msg) {
    const el = ensureAlertBar();
    el.textContent = String(msg || "Error");
    el.style.display = "block";
  }
  function clearError() {
    const el = document.getElementById("alert-bar");
    if (el) el.remove();
  }

  /* groups */
  function canonRunKey(s) {
    if (!s) return "";
    let t = String(s).trim().toLowerCase().replace(/^\{|\}$/g, "");
    if (/^[0-9a-f-]{36}$/.test(t) && t[8]==='-' && t[13]==='-' && t[18]==='-' && t[23]==='-') return t;
    if (/^[0-9a-f]{32}$/.test(t)) return `${t.slice(0,8)}-${t.slice(8,12)}-${t.slice(12,16)}-${t.slice(16,20)}-${t.slice(20)}`;
    return t;
  }
  function isConcreteRunKey(s) {
    const k = canonRunKey(s);
    return /^[0-9a-z-]{8,}$/.test(k);
  }
  function runIdFromUrl(url) {
    const file = (url.split("/").pop() || "");
    const stem = file.replace(/\.(png|jpg|jpeg)$/i, "");
    const first = stem.split("_")[0] || stem;
    return first || "unknown";
  }
  function buildGroups(frames, events) {
    const bad = [];
    const runKeys = Array.from(new Set(
      (events || []).map(e => {
        if (!e || typeof e.run !== "string") { bad.push(e); return null; }
        const k = canonRunKey(e.run);
        if (!isConcreteRunKey(k)) { bad.push(e); return null; }
        return k;
      }).filter(Boolean)
    ));
    if (runKeys.length === 0) {
      showError("No run keys in events");
      return [];
    }
    clearError();
    if (bad.length > 0) showError(`Some events missing run keys (${bad.length})`);
    const gs = runKeys.map(rk => {
      const indices = [];
      const frs = (frames || []).filter((u, i) => {
        const fk = canonRunKey(runIdFromUrl(u));
        if (fk === rk) { indices.push(i); return true; }
        return false;
      });
      return {
        runId: rk,
        frames: frs,
        indices,
        startGlobal: indices[0] ?? 0,
        endGlobal: indices.length ? indices[indices.length-1]
                                  : ((frames||[]).length ? (frames.length-1) : 0)
      };
    });
    return gs;
  }
  function curGroup() {
    return groups[gidx] || { runId:"-", frames:[], indices:[], startGlobal:0, endGlobal:0 };
  }
  function updateGroupLabel() {
    const g = curGroup();
    gLabel.textContent = `Run ${g.runId} (${gidx + 1}/${groups.length})`;
    gPrevBtn.disabled = gidx <= 0;
    gNextBtn.disabled = gidx >= Math.max(0, groups.length - 1);
  }

  /* frames */
  function stageCaptionFromUrl(url) {
    const file = (url.split("/").pop() || "");
    const stem = file.replace(/\.(png|jpg|jpeg)$/i, "");
    const parts = stem.split("_");
    if (parts.length <= 1) return prettifyStage(stem);
    parts.shift();
    return prettifyStage(parts.join("_"));
  }
  function prettifyStage(raw) {
    const map = { clahe: "CLAHE", yuv: "YUV" };
    if (map[raw]) return map[raw];
    const s = raw.replace(/_/g, " ");
    return s.replace(/\b([a-z])/g, m => m.toUpperCase());
  }
  function renderGroupFrames() {
    const g = curGroup();
    framesGrid.innerHTML = "";
    g.frames.forEach((src, i) => {
      const card = document.createElement("div");
      card.className = "thumb";
      card.dataset.ridx = i;

      const img = document.createElement("img");
      img.loading = "lazy";
      img.alt = `frame ${i+1} (run ${g.runId})`;
      img.src = src;

      const badge = document.createElement("div");
      badge.className = "idx";
      const globalI = g.indices[i];
      badge.textContent = `${globalI + 1}`;

      const cap = document.createElement("div");
      cap.className = "cap";
      const label = stageCaptionFromUrl(src);
      cap.textContent = label;
      cap.title = (src.split("/").pop() || "");

      card.append(img, badge, cap);
      framesGrid.appendChild(card);
      card.onclick = () => { ridx = i; updateFrameUI(); drawChart(); };
    });
    ridx = Math.min(ridx, Math.max(0, g.frames.length - 1));
    slider.max = Math.max(0, g.frames.length - 1);
    slider.value = ridx;
  }
  function updateFrameUI() {
    const g = curGroup();
    if (g.frames.length === 0) { clearUI(); return; }
    ridx = clamp(ridx, 0, g.frames.length - 1);
    slider.value = ridx;
    prevBtn.disabled = ridx === 0;
    nextBtn.disabled = ridx === g.frames.length - 1;
    frameInfo.textContent = `Frame ${ridx + 1} / ${g.frames.length} (global ${g.indices[ridx] + 1})`;
    [...framesGrid.querySelectorAll(".thumb")].forEach((el, i) =>
      el.classList.toggle("selected", i === ridx)
    );
    const selected = framesGrid.querySelector(`.thumb[data-ridx="${ridx}"]`);
    selected?.scrollIntoView({ block: "nearest", inline: "nearest" });
  }
  function clearUI() {
    framesGrid.innerHTML = "";
    slider.max = 0; slider.value = 0;
    prevBtn.disabled = true; nextBtn.disabled = true;
    gPrevBtn.disabled = true; gNextBtn.disabled = true;
    frameInfo.textContent = "";
    logList.innerHTML = "<div class='row muted'><div class='ev-left'><span class='ev-text'>No data</span></div></div>";
    logMeta.textContent = "";
    clearRuntimeBox();
    drawChart();
  }

  /* log */
  function renderUnifiedLog() {
    const s = current();
    const g = curGroup();
    const all = [];
    for (const e of (s.events || [])) {
      if (typeof e.run === "string" && e.run.length > 0) {
        if (e.run !== g.runId) continue;
        all.push({ ts: e.ts ?? null, badge: e.stage || "event", text: e.txt });
      }
    }
    all.sort((a,b) => (a.ts ?? Infinity) - (b.ts ?? Infinity));
    logMeta.textContent = `${all.length} items · Run ${g.runId}`;
    logList.innerHTML = all.map(rowHTML).join("") ||
      "<div class='row muted'><div class='ev-left'><span class='ev-text'>No events</span></div></div>";
  }
  function rowHTML(r) {
    const ts = (r.ts != null) ? fmtTime(r.ts) : "";
    const aux = ts;
    return `
      <div class="row" title="${escapeHtml(r.text)}">
        <div class="ev-left">
          <span class="ev-badge">${escapeHtml(r.badge)}</span>
          <span class="ev-text">${escapeHtml(r.text)}</span>
        </div>
        <div class="ev-aux">${escapeHtml(aux)}</div>
      </div>
    `;
  }

  /* controls */
  function wireControls() {
    prevBtn.onclick  = () => { if (ridx > 0) { ridx--; updateFrameUI(); drawChart(); } };
    nextBtn.onclick  = () => {
      const max = Math.max(0, curGroup().frames.length - 1);
      if (ridx < max) { ridx++; updateFrameUI(); drawChart(); }
    };
    slider.oninput   = e => { ridx = +e.target.value; updateFrameUI(); drawChart(); };
    slider.onchange  = slider.oninput;
    gPrevBtn.onclick = () => { if (gidx > 0) { gidx--; ridx = 0; renderGroupFrames(); updateFrameUI(); drawChart(); renderUnifiedLog(); updateGroupLabel(); } };
    gNextBtn.onclick = () => { if (gidx < groups.length - 1) { gidx++; ridx = 0; renderGroupFrames(); updateFrameUI(); drawChart(); renderUnifiedLog(); updateGroupLabel(); } };
    window.addEventListener("keydown", (e) => {
      if (!sid) return;
      if (e.key === "ArrowLeft") prevBtn.click();
      if (e.key === "ArrowRight") nextBtn.click();
    });
    openBtn.onclick = openModal;
    modal.addEventListener("click", (e) => { if (e.target.hasAttribute("data-close")) closeModal(); });
    modal.querySelector(".modal__close").onclick = closeModal;
    mPrev.onclick = () => { prevBtn.click(); updateModalImage(); };
    mNext.onclick = () => { nextBtn.click(); updateModalImage(); };
    window.addEventListener("resize", drawChart);
  }

  /* modal */
  function openModal() {
    if (!sid) return;
    updateModalImage();
    modal.classList.add("open");
    modal.setAttribute("aria-hidden", "false");
  }
  function closeModal() {
    modal.classList.remove("open");
    modal.setAttribute("aria-hidden", "true");
  }
  function updateModalImage() {
    const g = curGroup();
    if (g.frames.length === 0) return;
    modalImg.src = g.frames[ridx];
    const label = stageCaptionFromUrl(g.frames[ridx]);
    document.getElementById("modal-title").textContent =
      `Run ${g.runId} • ${label} (${ridx + 1}/${g.frames.length})`;
  }

  /* runtime */
  function clearRuntimeBox() {
    qNowEl.textContent = "-";
    qPeakEl.textContent = "-";
    sbEl.textContent = "-";
    actEl.textContent = "-";
  }
  function updateRuntimeBox() {
    const s = sid && seriesCache.get(sid);
    if (!s || !s.ticks || s.ticks.length === 0) { clearRuntimeBox(); return; }
    const last = s.ticks[s.ticks.length - 1];
    const peak = s.ticks.reduce((m, t) => Math.max(m, safeNum(t.maxQueue, 0)), 0);
    qNowEl.textContent = safeNum(last.queue, "-");
    qPeakEl.textContent = peak === 0 ? "-" : peak.toString();
    sbEl.textContent = last.standby ? "Yes" : "No";
    actEl.textContent = last.active ? "Yes" : "No";
  }

  /* chart */
  function drawChart() {
    const ctx = canvas.getContext("2d");
    const W  = canvas.clientWidth || canvas.parentElement.clientWidth || 900;
    const H  = canvas.clientHeight || 220;
    const dpr = window.devicePixelRatio || 1;
    canvas.width  = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);
    ctx.fillStyle = "#fff";
    ctx.fillRect(0, 0, W, H);

    const ser = sid && seriesCache.get(sid);
    const health = ser && Array.isArray(ser.health) ? ser.health : [];
    const s = current();
    const g = curGroup();

    const padL = 52, padR = 60, padT = 20, padB = 34;
    const plotW = Math.max(0, W - padL - padR);
    const plotH = Math.max(0, H - padT - padB);

    guideFrame(ctx, W, H);
    drawAxes(ctx, padL, padT, plotW, plotH);

    ctx.fillStyle = "#6c7786"; ctx.font = "12px system-ui, sans-serif";
    ctx.save(); ctx.translate(14, padT + plotH/2); ctx.rotate(-Math.PI/2);
    ctx.fillText("CPU / RAM (%)", 0, 0); ctx.restore();
    ctx.fillText("Temp (°C)", padL + plotW + 6, padT - 6);

    if (!health || health.length < 2) {
      caption.textContent = "No health data";
      drawGroupMarkersFromFrames(ctx, padL, padT, plotW, plotH, s, g);
      updateLegendValues();
      return;
    }

    const n = health.length;
    const xAt = i => padL + (i / (n - 1)) * plotW;
    const yPct = v => padT + (1 - clamp01(v / 100)) * plotH;
    const tMin = Math.min(...health.map(h => safeNum(h.temp, 0)));
    const tMax = Math.max(...health.map(h => safeNum(h.temp, 0)));
    const tRange = (tMax > tMin) ? (tMax - tMin) : 1;
    const yTemp = t => padT + (1 - ((t - tMin) / tRange)) * plotH;

    gridY(ctx, padL, padT, plotW, plotH, [0,25,50,75,100], yPct, "#eef2fb");
    axisRightLabels(ctx, padL, padT, plotW, plotH, tMin, tMax, yTemp);

    function drawSeries(arr, yFn, color, dash) {
      ctx.save(); ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.setLineDash(dash || []);
      ctx.beginPath();
      arr.forEach((h, i) => { const x=xAt(i), y=yFn(h); i===0 ? ctx.moveTo(x,y) : ctx.lineTo(x,y); });
      ctx.stroke(); ctx.restore();
    }
    if (visible.cpu)  drawSeries(health, h => yPct(safeNum(h.cpu, 0)),  "#005ff9", []);
    if (visible.ram)  drawSeries(health, h => yPct(safeNum(h.ram, 0)),  "#00a87e", [6,4]);
    if (visible.temp) drawSeries(health, h => yTemp(safeNum(h.temp, 0)), "#ff6a00", [3,3]);

    let iActive;
    if (hoverIndex != null) {
      iActive = clamp(hoverIndex, 0, n - 1);
      caption.textContent = "Hover to inspect";
    } else if (g.frames.length > 0 && g.indices.length > 0) {
      const totalFrames = Math.max(1, s.frames.length);
      const globalIdx = g.indices[ridx] ?? 0;
      const ratio = (totalFrames <= 1) ? 0 : (globalIdx / (totalFrames - 1));
      iActive = Math.round(ratio * (n - 1));
      caption.textContent = "Values at current frame";
    } else {
      iActive = n - 1;
      caption.textContent = "Latest values";
    }

    const xActive = xAt(iActive);
    vline(ctx, xActive, padT, padT + plotH, "#111", 1.25);
    updateLegendValues(health[iActive]);

    drawGroupMarkersFromFrames(ctx, padL, padT, plotW, plotH, s, g);
  }

  function drawGroupMarkersFromFrames(ctx, L, T, W, H, session, group) {
    const total = Math.max(1, session.frames.length);
    const startR = (total <= 1) ? 0 : (group.startGlobal / (total - 1));
    const endR   = (total <= 1) ? 0 : (group.endGlobal / (total - 1));
    const x0 = L + startR * W;
    const x1 = L + endR   * W;
    ctx.strokeStyle = "#9aa4b5";
    ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(x0, T); ctx.lineTo(x1, T); ctx.stroke();
    vline(ctx, x0, T, T + H, "#9aa4b5");
    vline(ctx, x1, T, T + H, "#9aa4b5");
  }

  /* drawing */
  function guideFrame(ctx, W, H) {
    ctx.strokeStyle = "#e7ebf3";
    ctx.strokeRect(0.5, 0.5, W - 1, H - 1);
  }
  function drawAxes(ctx, L, T, W, H) {
    ctx.strokeStyle = "#cfd6e0";
    ctx.beginPath();
    ctx.moveTo(L, T + H); ctx.lineTo(L + W, T + H);
    ctx.moveTo(L, T);     ctx.lineTo(L, T + H);
    ctx.stroke();
  }
  function gridY(ctx, L, T, W, H, marks, yMap, color) {
    ctx.strokeStyle = color;
    ctx.lineWidth = 1;
    for (const m of marks) {
      const y = yMap(m);
      ctx.beginPath(); ctx.moveTo(L, y); ctx.lineTo(L + W, y); ctx.stroke();
      ctx.fillStyle = "#6c7786";
      ctx.font = "12px system-ui, sans-serif";
      ctx.fillText(`${m}%`, L - 34, y + 4);
    }
  }
  function axisRightLabels(ctx, L, T, W, H, tMin, tMax, yMap) {
    ctx.fillStyle = "#6c7786";
    ctx.font = "12px system-ui, sans-serif";
    const ticks = 4;
    for (let i=0;i<=ticks;i++){
      const t = tMin + (i*(tMax - tMin))/ticks;
      const y = yMap(t);
      ctx.fillText(`${t.toFixed(0)}°C`, L + W + 8, y + 4);
    }
  }
  function vline(ctx, x, y0, y1, color, width=1) {
    ctx.strokeStyle = color;
    ctx.lineWidth = width;
    ctx.beginPath(); ctx.moveTo(x, y0); ctx.lineTo(x, y1); ctx.stroke();
  }

  /* utils */
  function clamp(v, a, b) { return Math.max(a, Math.min(b, v)); }
  function clamp01(v) { return Math.max(0, Math.min(1, v)); }
  function safeNum(v, fallback=0) {
    const n = Number(v);
    return Number.isFinite(n) ? n : fallback;
  }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
  }
  function fmtTime(ts) {
    try {
      const d = new Date(Number(ts));
      return d.toLocaleTimeString([], { hour:'2-digit', minute:'2-digit', second:'2-digit' });
    } catch { return ""; }
  }

  /* reload */
  async function reloadSessions() {
    try {
      const res = await fetch("/reload", { method: "POST" });
      if (!res.ok) throw new Error(`POST /reload failed: ${res.status}`);
      await fetchSessions();
      renderSessionList();
      if (!sid && sessions.length > 0) {
        await selectSession(sessions[0].id);
      } else if (sid && !sessions.find(s => s.id === sid)) {
        await selectSession(sessions[0]?.id || null);
      } else {
        const s = current();
        groups = buildGroups(s.frames, s.events);
        gidx = clamp(gidx, 0, Math.max(0, groups.length - 1));
        ridx = 0;
        renderGroupFrames();
        updateFrameUI();
        await fetchSeries(sid);
        drawChart();
        updateRuntimeBox();
        renderUnifiedLog();
        updateGroupLabel();
      }
    } catch (err) {
      console.error(err);
    }
  }
  window.replayReload = reloadSessions;
})();