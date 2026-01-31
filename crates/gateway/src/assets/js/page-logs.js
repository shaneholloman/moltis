// ── Logs page ───────────────────────────────────────────────
import * as S from "./state.js";
import { sendRpc } from "./helpers.js";
import { registerPage } from "./router.js";

registerPage("/logs", function initLogs(container) {
  var paused = false;
  var maxEntries = 2000;

  container.style.cssText = "flex-direction:column;padding:0;overflow:hidden;";

  var toolbar = document.createElement("div");
  toolbar.style.cssText = "display:flex;align-items:center;gap:8px;padding:8px 16px;border-bottom:1px solid var(--border);flex-shrink:0;flex-wrap:wrap;";

  var levelSelect = document.createElement("select");
  levelSelect.style.cssText = "background:var(--surface2);border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);font-size:.78rem;padding:4px 8px;font-family:var(--font-body);";
  var allOpt = document.createElement("option");
  allOpt.value = ""; allOpt.textContent = "All levels"; allOpt.selected = true;
  levelSelect.appendChild(allOpt);
  ["trace","debug","info","warn","error"].forEach(function (lvl) {
    var opt = document.createElement("option");
    opt.value = lvl; opt.textContent = lvl.toUpperCase();
    levelSelect.appendChild(opt);
  });

  var targetInput = document.createElement("input");
  targetInput.type = "text"; targetInput.placeholder = "Filter target\u2026";
  targetInput.style.cssText = "background:var(--surface2);border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);font-size:.78rem;padding:4px 8px;width:140px;font-family:var(--font-body);";

  var searchInput = document.createElement("input");
  searchInput.type = "text"; searchInput.placeholder = "Search\u2026";
  searchInput.style.cssText = "background:var(--surface2);border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);font-size:.78rem;padding:4px 8px;width:160px;font-family:var(--font-body);";

  var pauseBtn = document.createElement("button");
  pauseBtn.textContent = "Pause";
  pauseBtn.style.cssText = "background:var(--surface2);border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);font-size:.78rem;padding:4px 10px;cursor:pointer;";

  var clearBtn = document.createElement("button");
  clearBtn.textContent = "Clear";
  clearBtn.style.cssText = "background:var(--surface2);border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);font-size:.78rem;padding:4px 10px;cursor:pointer;";

  var countLabel = document.createElement("span");
  countLabel.style.cssText = "color:var(--muted);font-size:.72rem;margin-left:auto;";
  countLabel.textContent = "0 entries";

  toolbar.appendChild(levelSelect); toolbar.appendChild(targetInput);
  toolbar.appendChild(searchInput); toolbar.appendChild(pauseBtn);
  toolbar.appendChild(clearBtn); toolbar.appendChild(countLabel);
  container.appendChild(toolbar);

  var logArea = document.createElement("div");
  logArea.style.cssText = "flex:1;overflow-y:auto;font-family:var(--font-mono);font-size:.78rem;line-height:1.5;padding:0;";
  container.appendChild(logArea);

  var entryCount = 0;

  function levelColor(level) {
    var l = level.toUpperCase();
    if (l === "ERROR") return "var(--error)";
    if (l === "WARN") return "var(--warn)";
    if (l === "DEBUG") return "var(--muted)";
    if (l === "TRACE") return "color-mix(in oklab, var(--muted) 60%, transparent)";
    return "var(--text)";
  }

  function levelBg(level) {
    var l = level.toUpperCase();
    if (l === "ERROR") return "rgba(239,68,68,0.08)";
    if (l === "WARN") return "rgba(245,158,11,0.06)";
    return "transparent";
  }

  function renderEntry(entry) {
    var row = document.createElement("div");
    row.style.cssText = "display:flex;gap:8px;padding:1px 16px;background:" + levelBg(entry.level) + ";border-bottom:1px solid var(--border);";
    var ts = document.createElement("span");
    ts.style.cssText = "color:var(--muted);flex-shrink:0;min-width:85px;";
    var d = new Date(entry.ts);
    ts.textContent = d.toLocaleTimeString([], { hour:"2-digit", minute:"2-digit", second:"2-digit" }) + "." + String(d.getMilliseconds()).padStart(3, "0");
    var lvl = document.createElement("span");
    lvl.style.cssText = "color:" + levelColor(entry.level) + ";flex-shrink:0;min-width:42px;font-weight:600;";
    lvl.textContent = entry.level.toUpperCase().substring(0, 5);
    var tgt = document.createElement("span");
    tgt.style.cssText = "color:var(--muted);flex-shrink:0;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;";
    tgt.textContent = entry.target;
    var msg = document.createElement("span");
    msg.style.cssText = "color:var(--text);white-space:pre-wrap;word-break:break-all;min-width:0;";
    msg.textContent = entry.message;
    if (entry.fields && Object.keys(entry.fields).length > 0) {
      msg.textContent += " " + Object.keys(entry.fields).map(function (k) { return k + "=" + entry.fields[k]; }).join(" ");
    }
    row.appendChild(ts); row.appendChild(lvl); row.appendChild(tgt); row.appendChild(msg);
    return row;
  }

  function appendEntry(entry) {
    var row = renderEntry(entry);
    logArea.appendChild(row);
    entryCount++;
    while (logArea.childNodes.length > maxEntries) { logArea.removeChild(logArea.firstChild); entryCount--; }
    countLabel.textContent = entryCount + " entries";
    if (!paused) {
      var atBottom = logArea.scrollHeight - logArea.scrollTop - logArea.clientHeight < 60;
      if (atBottom) logArea.scrollTop = logArea.scrollHeight;
    }
  }

  function matchesFilter(entry) {
    var minLevel = levelSelect.value;
    if (minLevel) {
      var levels = ["trace","debug","info","warn","error"];
      if (levels.indexOf(entry.level.toLowerCase()) < levels.indexOf(minLevel)) return false;
    }
    var tgtVal = targetInput.value.trim();
    if (tgtVal && entry.target.indexOf(tgtVal) === -1) return false;
    var searchVal = searchInput.value.trim().toLowerCase();
    if (searchVal && entry.message.toLowerCase().indexOf(searchVal) === -1 && entry.target.toLowerCase().indexOf(searchVal) === -1) return false;
    return true;
  }

  sendRpc("logs.list", {
    level: levelSelect.value || undefined,
    target: targetInput.value.trim() || undefined,
    search: searchInput.value.trim() || undefined,
    limit: 500
  }).then(function (res) {
    if (!res || !res.ok) return;
    var entries = (res.payload && res.payload.entries) || [];
    entries.forEach(function (e) { appendEntry(e); });
    logArea.scrollTop = logArea.scrollHeight;
  });

  S.setLogsEventHandler(function (entry) {
    if (paused) return;
    if (!matchesFilter(entry)) return;
    appendEntry(entry);
  });

  function refetch() {
    logArea.textContent = "";
    entryCount = 0;
    sendRpc("logs.list", {
      level: levelSelect.value || undefined,
      target: targetInput.value.trim() || undefined,
      search: searchInput.value.trim() || undefined,
      limit: 500
    }).then(function (res) {
      if (!res || !res.ok) return;
      var entries = (res.payload && res.payload.entries) || [];
      entries.forEach(function (e) { appendEntry(e); });
      logArea.scrollTop = logArea.scrollHeight;
    });
  }

  levelSelect.addEventListener("change", refetch);
  var filterTimeout;
  function debouncedRefetch() { clearTimeout(filterTimeout); filterTimeout = setTimeout(refetch, 300); }
  targetInput.addEventListener("input", debouncedRefetch);
  searchInput.addEventListener("input", debouncedRefetch);

  pauseBtn.addEventListener("click", function () {
    paused = !paused;
    pauseBtn.textContent = paused ? "Resume" : "Pause";
    pauseBtn.style.borderColor = paused ? "var(--warn)" : "var(--border)";
    if (!paused) logArea.scrollTop = logArea.scrollHeight;
  });

  clearBtn.addEventListener("click", function () {
    logArea.textContent = ""; entryCount = 0; countLabel.textContent = "0 entries";
  });
}, function teardownLogs() {
  S.setLogsEventHandler(null);
});
