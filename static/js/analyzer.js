/* Result analyzer — the detail view for a single urlscan.io scan.
 *
 * Talks only to this app's own /api/* endpoints, which add the API-Key header
 * server-side. Everything rendered here came from a scanned page, so it is
 * treated as hostile input: nodes are built with createElement and filled with
 * textContent, never innerHTML, and a resource URL is never turned into a live
 * link. Copy it or pivot on it instead.
 *
 * Public surface, used by app.js:
 *   URLScanAnalyzer.init({ getKey, onPivot })
 *   URLScanAnalyzer.open(uuid)
 *   URLScanAnalyzer.close()
 *   URLScanAnalyzer.clearCache()
 */

window.URLScanAnalyzer = (function () {
  "use strict";

  var RESULT_PREFIX = "urlscan-analyzer.result.";
  var ANALYSIS_PREFIX = "urlscan-analyzer.analysis.";
  var UUID_SHAPE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

  var hooks = { getKey: null, onPivot: null };

  var state = {
    uuid: null,
    data: null,
    analysis: null,
    hashSeen: {},      /* hash value -> number of scans in the urlscan corpus */
    busy: false,
    lastFocus: null,
    panelFocus: null,
    ready: false
  };

  var el = {};

  /* ---------------------------------------------------------------- utils */

  function node(tag, cls, value) {
    var element = document.createElement(tag);
    if (cls) element.className = cls;
    if (value !== null && value !== undefined) element.textContent = String(value);
    return element;
  }

  function clear(target) {
    if (target) target.textContent = "";
  }

  function fmt(value) {
    return typeof value === "number" && isFinite(value) ? value.toLocaleString() : String(value);
  }

  function bytes(value) {
    if (typeof value !== "number" || !isFinite(value) || value < 0) return "—";
    if (value < 1024) return value + " B";
    var kb = value / 1024;
    if (kb < 1024) return (kb < 10 ? kb.toFixed(1) : Math.round(kb)) + " KB";
    var mb = kb / 1024;
    return (mb < 10 ? mb.toFixed(2) : mb.toFixed(1)) + " MB";
  }

  function formatTime(iso) {
    if (!iso) return "Not recorded";
    var when = new Date(iso);
    if (isNaN(when.getTime())) return String(iso);
    return when.toLocaleString(undefined, {
      year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit"
    });
  }

  function shortDate(iso) {
    if (!iso) return "—";
    var when = new Date(iso);
    if (isNaN(when.getTime())) return String(iso);
    return when.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "2-digit" });
  }

  function truncate(value, limit) {
    var text = String(value === null || value === undefined ? "" : value);
    return text.length > limit ? text.slice(0, limit) + "…" : text;
  }

  function toast(message) {
    clearTimeout(toast._timer);
    if (!toast._node) {
      toast._node = node("div", "toast");
      toast._node.setAttribute("role", "status");
    }
    toast._node.textContent = message;
    document.body.appendChild(toast._node);
    toast._timer = setTimeout(function () {
      if (toast._node && toast._node.parentNode) toast._node.parentNode.removeChild(toast._node);
    }, 2200);
  }

  function copyText(value, button) {
    var done = function () {
      if (button) {
        var original = button.textContent;
        button.classList.add("is-done");
        button.textContent = "Copied";
        setTimeout(function () {
          button.classList.remove("is-done");
          button.textContent = original;
        }, 1200);
      }
      toast("Copied to clipboard");
    };

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(done, function () { fallbackCopy(value, done); });
    } else {
      fallbackCopy(value, done);
    }
  }

  function fallbackCopy(value, done) {
    /* clipboard.writeText needs a secure context; plain HTTP deployments land here. */
    var area = document.createElement("textarea");
    area.value = value;
    area.setAttribute("readonly", "readonly");
    area.style.position = "fixed";
    area.style.top = "-1000px";
    document.body.appendChild(area);
    area.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    document.body.removeChild(area);
    if (ok) { done(); } else { toast("This browser blocked the clipboard. Select the text to copy it."); }
  }

  function copyButton(value, label) {
    var button = node("button", "copy", label || "Copy");
    button.type = "button";
    button.title = "Copy to clipboard";
    button.addEventListener("click", function (event) {
      event.stopPropagation();
      copyText(value, button);
    });
    return button;
  }

  function withCopy(value, fallback) {
    /* A value plus its copy button, or a plain dash when there is nothing. */
    var wrap = document.createDocumentFragment();
    if (value === null || value === undefined || value === "") {
      wrap.appendChild(node("span", "", fallback || "Not recorded"));
      return wrap;
    }
    wrap.appendChild(node("span", "", value));
    wrap.appendChild(copyButton(String(value)));
    return wrap;
  }

  function pivot(query) {
    if (typeof hooks.onPivot === "function") {
      hooks.onPivot(query);
    } else {
      toast("The main dashboard is not available to search from here.");
    }
  }

  /* --------------------------------------------------------------- storage */

  function cacheRead(prefix, uuid) {
    try {
      var raw = window.sessionStorage.getItem(prefix + uuid);
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      return null;
    }
  }

  function cacheWrite(prefix, uuid, payload) {
    try {
      window.sessionStorage.setItem(prefix + uuid, JSON.stringify(payload));
    } catch (e) {
      /* Storage full or blocked. The panel works without a cache; drop it. */
      clearCache();
    }
  }

  function clearCache() {
    try {
      var doomed = [];
      for (var i = 0; i < window.sessionStorage.length; i += 1) {
        var key = window.sessionStorage.key(i);
        if (key && (key.indexOf(RESULT_PREFIX) === 0 || key.indexOf(ANALYSIS_PREFIX) === 0)) {
          doomed.push(key);
        }
      }
      doomed.forEach(function (key) { window.sessionStorage.removeItem(key); });
    } catch (e) {
      /* nothing to clear */
    }
  }

  /* --------------------------------------------------------------- request */

  function request(path, params) {
    var url = new URL(path, window.location.origin);
    Object.keys(params || {}).forEach(function (key) {
      var value = params[key];
      if (value !== null && value !== undefined && value !== "") url.searchParams.set(key, value);
    });

    var headers = { Accept: "application/json" };
    var key = typeof hooks.getKey === "function" ? hooks.getKey() : "";
    if (key) headers["X-URLScan-Key"] = key;

    return fetch(url.toString(), { headers: headers, cache: "no-store" }).then(function (response) {
      return response.json().catch(function () {
        throw new Error("The server returned a response this page could not read.");
      }).then(function (body) {
        if (!response.ok || body.ok === false) {
          var error = new Error((body.error && body.error.message) || "Request failed.");
          error.code = body.error && body.error.code;
          throw error;
        }
        return body;
      });
    });
  }

  function setBusy(busy, label) {
    state.busy = busy;
    el.loading.hidden = !busy;
    el.loadingLabel.textContent = label || "Reading the scan…";
    el.pull.disabled = busy;
    el.pull.textContent = busy ? "Pulling…" : "Pull result from URLScan";
  }

  function showError(message) {
    el.alertMsg.textContent = message;
    el.alert.hidden = false;
  }

  function clearError() {
    el.alert.hidden = true;
    clear(el.alertMsg);
  }

  /* ---------------------------------------------------------------- chips */

  function chip(band, label) {
    var element = node("span", "chip chip--" + band);
    element.appendChild(node("span", "chip__dot"));
    element.appendChild(node("span", "", label));
    return element;
  }

  function statusCell(status, statusText) {
    var cls = "status-code status-code--none";
    var label = "—";
    if (typeof status === "number") {
      label = String(status);
      if (status >= 400) cls = "status-code status-code--bad";
      else if (status >= 300) cls = "status-code status-code--warn";
      else cls = "status-code status-code--ok";
    }
    var element = node("span", cls, label);
    if (statusText) element.title = statusText;
    return element;
  }

  function pill(category, label) {
    return node("span", "pill pill--" + (category || "unknown"), label || "Unclassified");
  }

  /* ---------------------------------------------------------------- cards */

  function card(id, title, subtitle) {
    var section = node("section", "acard");
    section.id = id;

    var head = node("button", "acard__head");
    head.type = "button";
    head.setAttribute("aria-expanded", "true");
    head.appendChild(node("h3", "", title));
    var count = node("span", "acard__count", subtitle || "");
    head.appendChild(count);
    var chevron = node("span", "acard__chevron", "▾");
    chevron.setAttribute("aria-hidden", "true");
    head.appendChild(chevron);

    var body = node("div", "acard__body");
    body.id = id + "-body";
    head.setAttribute("aria-controls", body.id);

    head.addEventListener("click", function () {
      var collapsed = section.classList.toggle("is-collapsed");
      head.setAttribute("aria-expanded", String(!collapsed));
    });

    section.appendChild(head);
    section.appendChild(body);
    section._body = body;
    section._count = count;
    return section;
  }

  function stat(value, label, title) {
    var element = node("div", "stat");
    element.appendChild(node("div", "stat__value", value));
    element.appendChild(node("div", "stat__label", label));
    if (title) element.title = title;
    return element;
  }

  function barRow(label, value, max, valueLabel, severity) {
    var row = node("div", "bar-row" + (severity ? " bar-row--sev-" + severity : ""));
    row.appendChild(node("div", "bar-row__label", label));
    var track = node("div", "bar-row__track");
    var fill = node("div", "bar-row__fill");
    var share = max > 0 ? Math.max(value > 0 ? 2 : 0, Math.round((value / max) * 100)) : 0;
    fill.style.width = share + "%";
    track.appendChild(fill);
    row.appendChild(track);
    row.appendChild(node("div", "bar-row__value", valueLabel));
    return row;
  }

  /* -------------------------------------------------------------- summary */

  function renderSummary(container) {
    var summary = state.data.summary;
    var counts = summary.counts || {};

    var grid = node("div", "summary");

    var shot = node("button", "summary__shot");
    shot.type = "button";
    var image = document.createElement("img");
    image.alt = "Screenshot captured during the scan of " + (summary.domain || "this page");
    image.loading = "lazy";
    image.decoding = "async";
    shot.appendChild(image);
    shot.appendChild(node("span", "summary__missing", "No screenshot stored"));
    if (summary.screenshot_url) {
      image.src = summary.screenshot_url;
      image.addEventListener("error", function () { shot.classList.add("is-blank"); });
      shot.title = "Open the full screenshot on urlscan.io";
      shot.addEventListener("click", function () {
        window.open(summary.screenshot_url, "_blank", "noopener,noreferrer");
      });
    } else {
      shot.classList.add("is-blank");
      shot.disabled = true;
    }
    grid.appendChild(shot);

    var facts = node("dl", "kv");

    function fact(label, value, options) {
      options = options || {};
      var wrap = document.createElement("div");
      wrap.appendChild(node("dt", "", label));
      var dd = node("dd", options.mono ? "mono" : "");
      if (options.nodes) {
        options.nodes.forEach(function (child) { dd.appendChild(child); });
      } else if (options.copy) {
        dd.appendChild(withCopy(value));
      } else {
        dd.textContent = value === null || value === undefined || value === "" ? "Not recorded" : String(value);
      }
      wrap.appendChild(dd);
      facts.appendChild(wrap);
    }

    fact("Website title", summary.title || "No title element");
    fact("Domain", summary.domain, { copy: true, mono: true });
    fact("IP address", summary.ip, { copy: true, mono: true });

    var asnNodes = [];
    if (summary.asn) {
      var asnButton = node("button", "link-btn", summary.asn);
      asnButton.type = "button";
      asnButton.title = "Search the main dashboard for this ASN";
      asnButton.addEventListener("click", function () { pivot("page.asn:" + summary.asn); });
      asnNodes.push(asnButton);
      if (summary.asn_name) asnNodes.push(node("span", "", summary.asn_name));
      asnNodes.push(copyButton(summary.asn + (summary.asn_name ? " " + summary.asn_name : "")));
    } else {
      asnNodes.push(node("span", "", "Not recorded"));
    }
    fact("ASN", null, { nodes: asnNodes });

    fact("Scan date", formatTime(summary.scan_time));
    fact("HTTP status", null, { nodes: [statusCell(typeof summary.status === "number" ? summary.status : null)] });
    fact("Server", summary.server);
    fact("Location", [summary.city, summary.country].filter(Boolean).join(", ") || "Not recorded");
    fact("Reverse DNS", summary.ptr, { mono: true });
    fact("Content type", summary.mime_type, { mono: true });

    var tls = summary.tls || {};
    var certificate = tls.certificate || {};
    var tlsParts = [];
    if (tls.issuer) tlsParts.push(tls.issuer);
    if (typeof tls.valid_days === "number") {
      tlsParts.push(tls.valid_days < 0
        ? "expired " + Math.abs(tls.valid_days) + " days ago"
        : tls.valid_days + " days left");
    }
    if (typeof tls.age_days === "number") tlsParts.push("issued " + tls.age_days + " days before the scan");
    fact("TLS certificate", tlsParts.join(" · ") || "No certificate recorded");
    if (certificate.subject) {
      fact("Certificate subject", certificate.subject, { mono: true, copy: true });
    }

    fact("Visibility", summary.visibility);
    if (summary.tags && summary.tags.length) fact("Scan tags", summary.tags.join(", "));
    if (summary.technologies && summary.technologies.length) {
      fact("Detected technology", summary.technologies.map(function (tech) { return tech.name; }).join(", "));
    }

    grid.appendChild(facts);
    container.appendChild(grid);

    var urlBlock = node("div", "panel__section");
    urlBlock.appendChild(node("h4", "", "Scanned URL (not linked, on purpose)"));
    var urlBox = node("div", "panel__url", summary.url || summary.submitted_url || "Not recorded");
    urlBlock.appendChild(urlBox);
    var actions = node("div", "panel__actions");
    if (summary.url) actions.appendChild(copyButton(summary.url, "Copy URL"));
    if (summary.domain) {
      var domainPivot = node("button", "btn btn--ghost btn--small", "Search this domain");
      domainPivot.type = "button";
      domainPivot.addEventListener("click", function () { pivot('page.domain:"' + summary.domain + '"'); });
      actions.appendChild(domainPivot);
    }
    if (summary.apex_domain && summary.apex_domain !== summary.domain) {
      var apexPivot = node("button", "btn btn--ghost btn--small", "Search the apex domain");
      apexPivot.type = "button";
      apexPivot.addEventListener("click", function () { pivot('page.apexDomain:"' + summary.apex_domain + '"'); });
      actions.appendChild(apexPivot);
    }
    if (summary.ip) {
      var ipPivot = node("button", "btn btn--ghost btn--small", "Search this IP");
      ipPivot.type = "button";
      ipPivot.addEventListener("click", function () { pivot("page.ip:" + summary.ip); });
      actions.appendChild(ipPivot);
    }
    urlBlock.appendChild(actions);
    container.appendChild(urlBlock);

    var stats = node("div", "stats");
    stats.style.marginTop = "16px";
    stats.appendChild(stat(fmt(counts.requests || 0), "Requests"));
    stats.appendChild(stat(fmt(counts.domains || 0), "Domains contacted"));
    stats.appendChild(stat(fmt(counts.ips || 0), "Unique IPs"));
    stats.appendChild(stat(fmt(counts.unique_countries || counts.countries || 0), "Countries"));
    stats.appendChild(stat(fmt(counts.asns || 0), "Networks (ASNs)"));
    stats.appendChild(stat(bytes(counts.transfer_bytes || 0), "Transferred"));
    stats.appendChild(stat(fmt(counts.links || 0), "Outgoing links"));
    stats.appendChild(stat(fmt(counts.cookies || 0), "Cookies set"));
    if (counts.ads_blocked) stats.appendChild(stat(fmt(counts.ads_blocked), "Ad requests blocked"));
    if (typeof counts.secure_percentage === "number") {
      stats.appendChild(stat(counts.secure_percentage + "%", "Requests over TLS"));
    }
    container.appendChild(stats);
  }

  /* ------------------------------------------------------------- verdicts */

  function renderVerdicts(container) {
    var verdicts = state.data.verdicts;
    var engines = verdicts.engines || {};

    var bandLabels = {
      clean: "No verdict against this scan",
      low: "Low",
      suspicious: "Suspicious",
      malicious: "Malicious"
    };

    var hero = node("div", "hero hero--" + verdicts.band);
    var figure = node("div", "hero__figure");
    var number = node("div", "hero__number");
    number.appendChild(node("span", "", String(verdicts.threat_score)));
    number.appendChild(node("span", "hero__unit", "/100"));
    figure.appendChild(number);
    var gauge = node("div", "gauge");
    var gaugeFill = node("div", "gauge__fill");
    gaugeFill.style.width = Math.max(0, Math.min(100, verdicts.threat_score)) + "%";
    gauge.appendChild(gaugeFill);
    figure.appendChild(gauge);
    figure.appendChild(node("div", "hero__caption", "Threat score"));
    hero.appendChild(figure);

    var explain = node("div", "hero__text");
    var line = node("p");
    line.appendChild(chip(verdicts.band, bandLabels[verdicts.band] || verdicts.band));
    explain.appendChild(line);

    if (verdicts.has_verdicts) {
      explain.appendChild(node("p", "",
        "The score is the strongest opinion on record — urlscan's own classifier, the "
        + "security engines it queries, and community votes — not an average, so one "
        + "confident detection is not diluted by engines that stayed silent."));
    } else {
      explain.appendChild(node("p", "",
        "No engine, classifier or voter has expressed an opinion about this scan. "
        + "That is not the same as a clean bill of health: most scans are never reviewed."));
    }

    var counts = [];
    if (engines.engines_total) {
      counts.push(engines.malicious_total + " of " + engines.engines_total + " engines flagged it");
    }
    if (verdicts.community && verdicts.community.votes_total) {
      counts.push(verdicts.community.votes_malicious + " of " + verdicts.community.votes_total
        + " community votes called it malicious");
    }
    if (counts.length) explain.appendChild(node("p", "", counts.join(". ") + "."));
    hero.appendChild(explain);
    container.appendChild(hero);

    var labelled = [
      ["urlscan classifier", verdicts.urlscan],
      ["Security engines", { score: engines.score, malicious: engines.malicious_total > 0 }],
      ["Community", verdicts.community],
      ["Overall", verdicts.overall]
    ];
    var scoreStats = node("div", "stats");
    labelled.forEach(function (pair) {
      var value = pair[1] && typeof pair[1].score === "number" ? pair[1].score : null;
      scoreStats.appendChild(stat(value === null ? "—" : value, pair[0] + " score"));
    });
    container.appendChild(scoreStats);

    var tagBlocks = [
      ["Categories", (verdicts.overall.categories || []).concat(verdicts.urlscan.categories || [])],
      ["Tags", (verdicts.overall.tags || []).concat(verdicts.urlscan.tags || [])],
      ["Targeted brands", (verdicts.overall.brands || []).filter(Boolean)],
      ["Why urlscan flagged it", verdicts.urlscan.detection_details || []]
    ];
    tagBlocks.forEach(function (pair) {
      var values = pair[1].filter(function (value, index, all) {
        return value && all.indexOf(value) === index;
      });
      if (!values.length) return;
      var block = node("div", "panel__section");
      block.appendChild(node("h4", "", pair[0]));
      if (pair[0] === "Why urlscan flagged it") {
        values.forEach(function (value) { block.appendChild(node("p", "acard__note", value)); });
      } else {
        var row = node("div", "panel__actions");
        values.forEach(function (value) { row.appendChild(pill("unknown", value)); });
        block.appendChild(row);
      }
      container.appendChild(block);
    });

    var engineBlock = node("div", "panel__section");
    engineBlock.appendChild(node("h4", "", "Security engines"));
    if (engines.rows && engines.rows.length) {
      var grid = node("div", "engines");
      engines.rows.forEach(function (row) {
        var item = node("div", "engine engine--" + (row.malicious ? "malicious" : "benign"));
        item.appendChild(node("div", "engine__name", row.engine));
        var meta = node("div", "engine__meta");
        meta.appendChild(chip(row.malicious ? "malicious" : "clean", row.malicious ? "Malicious" : "Clean"));
        if (typeof row.score === "number") meta.appendChild(node("span", "match__meta", "score " + row.score));
        (row.categories || []).forEach(function (category) { meta.appendChild(pill("unknown", category)); });
        item.appendChild(meta);
        grid.appendChild(item);
      });
      engineBlock.appendChild(grid);
    } else {
      engineBlock.appendChild(node("p", "acard__note",
        "urlscan reported no per-engine verdicts for this scan. Engine coverage depends on the "
        + "account that submitted it and on when the scan ran."));
    }
    container.appendChild(engineBlock);
  }

  /* ---------------------------------------------------------------- files */

  function hashCell(file) {
    if (!file.hashes || !file.hashes.length) {
      return node("span", "hash-none", "No hash recorded");
    }

    var wrap = node("div", "hashes");
    file.hashes.forEach(function (item) {
      var badge = node("span", "hash hash--" + item.algorithm);
      badge.appendChild(node("span", "hash__label", item.algorithm));

      var value = node("button", "hash__value", truncate(item.value, 12));
      value.type = "button";
      value.title = item.value + "\nClick to find other scans that fetched this exact file";
      value.addEventListener("click", function (event) {
        event.stopPropagation();
        openHashPanel(item, file);
      });
      badge.appendChild(value);

      var seen = state.hashSeen[item.value];
      if (typeof seen === "number") {
        var seenLabel = node("span", "hash__seen", seen === 1 ? "1 scan" : fmt(seen) + " scans");
        seenLabel.title = seen + " scans in the urlscan.io corpus fetched this file. "
          + "Prevalence is not a malware verdict.";
        badge.appendChild(seenLabel);
      }

      badge.appendChild(copyButton(item.value, "⧉"));
      wrap.appendChild(badge);
    });
    return wrap;
  }

  function fileRows() {
    var files = state.data.files.slice();
    var term = (el.fileFilter.value || "").trim().toLowerCase();
    var apexOnly = el.apexToggle.getAttribute("aria-pressed") === "true";

    if (apexOnly) {
      files = files.filter(function (file) { return file.is_first_party; });
    }
    if (term) {
      files = files.filter(function (file) {
        return [
          file.filename, file.url, file.domain, file.mime_type, file.resource_type,
          file.category_label, file.service, file.ip, file.asn_name,
          (file.hashes || []).map(function (hash) { return hash.value; }).join(" ")
        ].filter(Boolean).join(" ").toLowerCase().indexOf(term) !== -1;
      });
    }

    var seenHashes = {};
    files = files.filter(function (file) {
      var hashes = file.hashes || [];
      var duplicate = hashes.some(function (hash) {
        return hash.value && seenHashes[hash.value];
      });
      hashes.forEach(function (hash) {
        if (hash.value) seenHashes[hash.value] = true;
      });
      return !duplicate;
    });

    var parts = (el.fileSort.value || "index:asc").split(":");
    var field = parts[0];
    var direction = parts[1] === "desc" ? -1 : 1;
    var pick = {
      index: function (file) { return file.index; },
      size: function (file) { return file.size_bytes || 0; },
      status: function (file) { return typeof file.status === "number" ? file.status : 0; },
      domain: function (file) { return (file.domain || "").toLowerCase(); },
      type: function (file) { return (file.mime_type || file.resource_type || "").toLowerCase(); },
      /* Sorting by hash groups byte-identical files next to each other. */
      hash: function (file) {
        return (file.hashes && file.hashes.length) ? file.hashes[0].value : "zzz";
      }
    }[field] || function (file) { return file.index; };

    files.sort(function (a, b) {
      var x = pick(a);
      var y = pick(b);
      if (x < y) return -1 * direction;
      if (x > y) return 1 * direction;
      return a.index - b.index;
    });

    return files;
  }

  function filePath(file) {
    if (!file.url) return file.filename || "(no name)";
    try {
      return new URL(file.url, window.location.origin).pathname || "/";
    } catch (error) {
      return file.filename || file.url;
    }
  }

  function renderFiles() {
    var files = fileRows();
    var stats = state.data.file_stats || {};

    clear(el.filesTable);

    var table = node("table", "atable");
    var head = document.createElement("thead");
    var headRow = document.createElement("tr");
    ["#", "File", "Type", "Size", "Status", "Domain", "Hashes"].forEach(function (label) {
      var cell = node("th", label === "Size" || label === "#" ? "num" : "", label);
      headRow.appendChild(cell);
    });
    head.appendChild(headRow);
    table.appendChild(head);

    var body = document.createElement("tbody");

    if (!files.length) {
      var emptyRow = document.createElement("tr");
      var emptyCell = node("td", "empty-row",
        state.data.files.length
          ? "No resource matches these filters."
          : "This scan recorded no resources.");
      emptyCell.colSpan = 7;
      emptyRow.appendChild(emptyCell);
      body.appendChild(emptyRow);
    }

    files.forEach(function (file, rowIndex) {
      var row = document.createElement("tr");
      if (file.failed) row.classList.add("is-failed");

      row.appendChild(node("td", "num", rowIndex + 1));

      var nameCell = document.createElement("td");
      var nameButton = node("button", "link-btn", filePath(file));
      nameButton.type = "button";
      nameButton.title = (file.url || "") + "\nClick for headers and network detail";
      nameButton.addEventListener("click", function () { openFilePanel(file); });
      nameCell.appendChild(nameButton);
      if (file.failed) {
        nameCell.appendChild(node("div", "match__meta", file.error || "Request failed"));
      }
      row.appendChild(nameCell);

      var typeCell = document.createElement("td");
      typeCell.appendChild(node("span", "", file.mime_type || file.resource_type || "—"));
      if (file.resource_type && file.mime_type) {
        typeCell.appendChild(node("div", "match__meta", file.resource_type));
      }
      row.appendChild(typeCell);

      row.appendChild(node("td", "num", bytes(file.size_bytes)));

      var statusTd = document.createElement("td");
      statusTd.appendChild(statusCell(file.status, file.status_text));
      row.appendChild(statusTd);

      var domainCell = document.createElement("td");
      if (file.domain) {
        var domainButton = node("button", "link-btn", file.domain);
        domainButton.type = "button";
        domainButton.title = "Search the main dashboard for this domain";
        domainButton.addEventListener("click", function () { pivot('page.domain:"' + file.domain + '"'); });
        domainCell.appendChild(domainButton);
      } else {
        domainCell.appendChild(node("span", "", "—"));
      }
      domainCell.appendChild(document.createElement("br"));
      domainCell.appendChild(pill(file.category, file.service || file.category_label));
      row.appendChild(domainCell);

      var hashTd = document.createElement("td");
      hashTd.appendChild(hashCell(file));
      row.appendChild(hashTd);

      body.appendChild(row);
    });

    table.appendChild(body);
    var wrap = node("div", "atable-wrap");
    wrap.appendChild(table);
    el.filesTable.appendChild(wrap);

    var shown = files.length;
    el.fileCount.textContent = shown === stats.total
      ? fmt(stats.total) + " resources"
      : fmt(shown) + " of " + fmt(stats.total) + " resources";

    clear(el.fileNote);
    var notes = [
      fmt(stats.first_party || 0) + " from the apex domain",
      fmt(stats.third_party || 0) + " third party",
      fmt(stats.with_hashes || 0) + " with a stored hash"
    ];
    if (stats.failed) notes.push(fmt(stats.failed) + " failed or blocked");
    if (stats.truncated) notes.push(fmt(stats.truncated) + " not shown (server cap)");
    el.fileNote.textContent = notes.join(" · ") + ". Filenames open the detail panel; domains pivot to a "
      + "new search; a hash badge looks for other scans that fetched the same bytes.";
  }

  /* -------------------------------------------------------------- domains */

  function renderDomains(container) {
    var domains = state.data.domains || [];
    var stats = state.data.domain_stats || {};

    var wrap = node("div", "atable-wrap");
    var table = node("table", "atable");
    var head = document.createElement("thead");
    var headRow = document.createElement("tr");
    ["Domain", "Requests", "Type", "Country", "Network", "Transferred"].forEach(function (label) {
      headRow.appendChild(node("th", label === "Requests" || label === "Transferred" ? "num" : "", label));
    });
    head.appendChild(headRow);
    table.appendChild(head);

    var body = document.createElement("tbody");
    if (!domains.length) {
      var emptyRow = document.createElement("tr");
      var emptyCell = node("td", "empty-row", "This scan recorded no domain statistics.");
      emptyCell.colSpan = 6;
      emptyRow.appendChild(emptyCell);
      body.appendChild(emptyRow);
    }

    var maxRequests = domains.reduce(function (most, row) {
      return Math.max(most, row.requests || 0);
    }, 0);

    domains.forEach(function (row) {
      var tr = document.createElement("tr");

      var nameCell = document.createElement("td");
      var nameButton = node("button", "link-btn", row.domain);
      nameButton.type = "button";
      nameButton.title = "Search the main dashboard for this domain";
      nameButton.addEventListener("click", function () { pivot('page.domain:"' + row.domain + '"'); });
      nameCell.appendChild(nameButton);

      var actions = node("div", "match__meta");
      var filesButton = node("button", "link-btn link-btn--plain", "show its files");
      filesButton.type = "button";
      filesButton.title = "Filter the file table to this domain";
      filesButton.addEventListener("click", function () {
        el.fileFilter.value = row.domain;
        el.apexToggle.setAttribute("aria-pressed", "false");
        el.apexToggle.textContent = "Show only apex domain files";
        renderFiles();
        document.getElementById("card-files").classList.remove("is-collapsed");
        document.getElementById("card-files").scrollIntoView({ behavior: "smooth", block: "start" });
      });
      actions.appendChild(filesButton);
      nameCell.appendChild(actions);
      tr.appendChild(nameCell);

      var requestCell = node("td", "num");
      requestCell.appendChild(node("span", "", fmt(row.requests || 0)));
      var track = node("div", "bar-row__track");
      track.style.marginTop = "4px";
      track.style.width = "70px";
      track.style.height = "6px";
      var fill = node("div", "bar-row__fill");
      fill.style.width = maxRequests ? Math.max(3, Math.round((row.requests / maxRequests) * 100)) + "%" : "0";
      track.appendChild(fill);
      requestCell.appendChild(track);
      tr.appendChild(requestCell);

      var typeCell = document.createElement("td");
      typeCell.appendChild(pill(row.category, row.category_label));
      if (row.service && row.service !== row.category_label) {
        typeCell.appendChild(node("div", "match__meta", row.service));
      }
      tr.appendChild(typeCell);

      tr.appendChild(node("td", "", row.country || row.country_code || "—"));

      var networkCell = document.createElement("td");
      if (row.asn) {
        var asnButton = node("button", "link-btn", row.asn);
        asnButton.type = "button";
        asnButton.addEventListener("click", function () { pivot("page.asn:" + row.asn); });
        networkCell.appendChild(asnButton);
        if (row.asn_name) networkCell.appendChild(node("div", "match__meta", row.asn_name));
      } else {
        networkCell.appendChild(node("span", "", "—"));
      }
      tr.appendChild(networkCell);

      tr.appendChild(node("td", "num", bytes(row.encoded_bytes || row.size_bytes || 0)));
      body.appendChild(tr);
    });

    table.appendChild(body);
    wrap.appendChild(table);
    container.appendChild(wrap);

    var categories = (stats.categories || []).filter(function (entry) { return entry.requests > 0; });
    if (categories.length > 1) {
      var figure = node("figure", "chart-figure");
      figure.style.marginTop = "16px";
      figure.appendChild(node("figcaption", "",
        "Requests by third-party type. Bar length is the only encoding; all bars share one colour."));
      var bars = node("div", "bars");
      var maxCategory = categories[0].requests;
      categories.forEach(function (entry) {
        bars.appendChild(barRow(
          entry.category_label,
          entry.requests,
          maxCategory,
          fmt(entry.requests) + " req · " + fmt(entry.domains) + (entry.domains === 1 ? " domain" : " domains")
        ));
      });
      figure.appendChild(bars);
      container.appendChild(figure);
    }

    container.appendChild(node("p", "acard__note",
      "Types come from database/domain_categories.csv, a local pattern table — not from urlscan. "
      + "Unclassified simply means the domain is not in that table."));
  }

  /* ----------------------------------------------------- content analysis */

  function renderContentAnalysis(container) {
    clear(container);

    var meta = state.data.meta || {};
    var controls = node("div", "panel__actions");
    var button = node("button", "btn btn--primary btn--small", "Analyze page content");
    button.type = "button";
    button.addEventListener("click", runAnalysis);
    controls.appendChild(button);

    if (!meta.content_analysis_available) {
      button.disabled = true;
      controls.appendChild(node("span", "acard__note",
        "This server could not load its risk keyword database, so content analysis is off."));
      container.appendChild(controls);
      return;
    }

    var database = meta.keyword_database || {};
    controls.appendChild(node("span", "acard__note",
      "Fetches the DOM urlscan stored for this scan and scores its visible text against "
      + fmt(database.keyword_count || 0) + " keywords in " + fmt(database.category_count || 0)
      + " categories."));
    container.appendChild(controls);

    var results = node("div");
    results.id = "an-analysis-results";
    container.appendChild(results);

    if (state.analysis) renderAnalysis(state.analysis, results);
  }

  function runAnalysis() {
    if (!state.uuid || state.busy) return;

    var cached = cacheRead(ANALYSIS_PREFIX, state.uuid);
    if (cached) {
      state.analysis = cached;
      renderAnalysis(cached, document.getElementById("an-analysis-results"));
      return;
    }

    clearError();
    setBusy(true, "Fetching the stored DOM and scoring its text…");
    request("/api/analyze/" + state.uuid, {})
      .then(function (body) {
        state.analysis = body;
        cacheWrite(ANALYSIS_PREFIX, state.uuid, body);
        renderAnalysis(body, document.getElementById("an-analysis-results"));
      })
      .catch(function (error) { showError(error.message || "Content analysis failed."); })
      .finally(function () { setBusy(false); });
  }

  function renderAnalysis(body, container) {
    if (!container) return;
    clear(container);

    var analysis = body.analysis || {};
    var bandLabels = { minimal: "Minimal", low: "Low", elevated: "Elevated", high: "High" };

    var hero = node("div", "hero hero--" + (analysis.band || "minimal"));
    hero.style.marginTop = "16px";
    var figure = node("div", "hero__figure");
    var number = node("div", "hero__number");
    number.appendChild(node("span", "", String(analysis.score || 0)));
    number.appendChild(node("span", "hero__unit", "%"));
    figure.appendChild(number);
    var gauge = node("div", "gauge");
    var fill = node("div", "gauge__fill");
    fill.style.width = Math.max(0, Math.min(100, analysis.score || 0)) + "%";
    gauge.appendChild(fill);
    figure.appendChild(gauge);
    figure.appendChild(node("div", "hero__caption", "Keyword risk score"));
    hero.appendChild(figure);

    var explain = node("div", "hero__text");
    var chipLine = node("p");
    chipLine.appendChild(chip(analysis.band || "minimal", (bandLabels[analysis.band] || "Minimal") + " keyword risk"));
    explain.appendChild(chipLine);

    if (body.empty) {
      explain.appendChild(node("p", "", body.message || "The stored DOM has no readable text."));
    } else {
      var sentence = fmt(analysis.unique_keywords) + " distinct scoring keywords matched "
        + fmt(analysis.total_hits) + " times across " + fmt(analysis.total_words)
        + " words, spread over " + fmt(analysis.category_breadth)
        + (analysis.category_breadth === 1 ? " category." : " categories.");
      if (analysis.context_keywords) {
        sentence += " A further " + fmt(analysis.context_keywords)
          + " topic words (bitcoin, blockchain and the like) were found but not scored: a page "
          + "is not suspicious for being about crypto.";
      }
      explain.appendChild(node("p", "", sentence));
      explain.appendChild(node("p", "acard__note", analysis.formula || ""));
    }
    hero.appendChild(explain);
    container.appendChild(hero);

    if (body.empty) {
      container.appendChild(node("p", "disclaimer", body.disclaimer || ""));
      return;
    }

    var stats = node("div", "stats");
    stats.appendChild(stat(fmt(analysis.total_words), "Words analysed"));
    stats.appendChild(stat(fmt(analysis.unique_keywords), "Scoring keywords",
      "Distinct keywords of weight 2 or higher"));
    stats.appendChild(stat(fmt(analysis.total_hits), "Their occurrences"));
    stats.appendChild(stat(fmt(analysis.signal_points), "Signal points",
      "What the score is computed from"));
    stats.appendChild(stat(fmt(analysis.category_breadth), "Categories hit"));
    stats.appendChild(stat("\u00d7" + Number(analysis.breadth_multiplier).toFixed(2),
      "Breadth multiplier", "How far the matches spread across categories"));
    stats.appendChild(stat(fmt(analysis.context_keywords || 0), "Context words",
      "Topic vocabulary such as bitcoin or blockchain. Reported, never scored."));
    container.appendChild(stats);

    var split = node("div", "split");

    var categories = (analysis.categories || []).slice(0, 12);
    if (categories.length) {
      var categoryFigure = node("figure", "chart-figure");
      categoryFigure.appendChild(node("figcaption", "",
        "Share of the signal points by category. One colour; length is the encoding."));
      var categoryBars = node("div", "bars");
      var maxShare = categories[0].points;
      categories.forEach(function (entry) {
        categoryBars.appendChild(barRow(
          entry.category.replace(/_/g, " "),
          entry.points,
          maxShare,
          entry.share + "% · " + fmt(entry.hits) + (entry.hits === 1 ? " hit" : " hits")
        ));
      });
      categoryFigure.appendChild(categoryBars);
      split.appendChild(categoryFigure);
    }

    var severity = (analysis.severity || []).filter(function (entry) { return entry.unique_keywords > 0; });
    if (severity.length) {
      var severityFigure = node("figure", "chart-figure");
      severityFigure.appendChild(node("figcaption", "",
        "Matched keywords by severity weight, dim to bright. Weight 1 is topic vocabulary and "
        + "does not contribute to the score."));
      var severityBars = node("div", "bars");
      var maxSeverity = severity.reduce(function (most, entry) {
        return Math.max(most, entry.unique_keywords);
      }, 0);
      (analysis.severity || []).forEach(function (entry) {
        severityBars.appendChild(barRow(
          entry.weight + " · " + entry.label + (entry.scored === false ? " (not scored)" : ""),
          entry.unique_keywords,
          maxSeverity,
          fmt(entry.unique_keywords),
          entry.weight
        ));
      });
      severityFigure.appendChild(severityBars);
      split.appendChild(severityFigure);
    }

    container.appendChild(split);

    var matches = analysis.matches || [];
    if (matches.length) {
      var matchHead = node("div", "panel__section");
      matchHead.appendChild(node("h4", "", "Matched keywords, strongest contribution first"));
      container.appendChild(matchHead);

      var list = node("div", "matches");
      var limit = 25;
      matches.slice(0, limit).forEach(function (match) { list.appendChild(matchCard(match)); });
      container.appendChild(list);

      if (matches.length > limit) {
        var more = node("button", "btn btn--ghost btn--small",
          "Show the remaining " + fmt(matches.length - limit) + " keywords");
        more.type = "button";
        more.style.marginTop = "10px";
        more.addEventListener("click", function () {
          matches.slice(limit).forEach(function (match) { list.appendChild(matchCard(match)); });
          more.remove();
        });
        container.appendChild(more);
      }
      if (analysis.matches_truncated) {
        container.appendChild(node("p", "acard__note",
          fmt(analysis.matches_truncated) + " further keywords were matched but not returned."));
      }
    }

    var textBlock = node("div", "panel__section");
    var toggle = node("button", "btn btn--ghost btn--small", "Show the extracted page text");
    toggle.type = "button";
    toggle.setAttribute("aria-expanded", "false");
    var box = node("pre", "excerpt-box", (body.text && body.text.excerpt) || "");
    box.hidden = true;
    toggle.addEventListener("click", function () {
      box.hidden = !box.hidden;
      toggle.textContent = box.hidden ? "Show the extracted page text" : "Hide the extracted page text";
      toggle.setAttribute("aria-expanded", String(!box.hidden));
    });
    textBlock.appendChild(node("h4", "", "Extracted text"));
    var textMeta = node("p", "acard__note",
      fmt((body.text && body.text.characters) || 0) + " characters of visible text"
      + (body.text && body.text.title ? " · page title: " + body.text.title : "")
      + (body.text && body.text.truncated_chars
        ? " · " + fmt(body.text.truncated_chars) + " characters beyond the server cap were not scored"
        : ""));
    textBlock.appendChild(textMeta);
    var textActions = node("div", "panel__actions");
    textActions.appendChild(toggle);
    if (body.text && body.text.excerpt) textActions.appendChild(copyButton(body.text.excerpt, "Copy text"));
    textBlock.appendChild(textActions);
    textBlock.appendChild(box);
    container.appendChild(textBlock);

    container.appendChild(node("p", "disclaimer", body.disclaimer || ""));

    if (body.meta) {
      container.appendChild(node("p", "acard__note",
        "DOM was " + bytes(body.meta.dom_bytes) + "; fetched in " + fmt(body.meta.fetch_ms)
        + " ms and scored in " + fmt(body.meta.score_ms) + " ms."));
    }
  }

  function matchCard(match) {
    var item = node("div", "match match--sev-" + match.weight);
    var head = node("div", "match__head");
    head.appendChild(node("span", "match__word", match.keyword));
    head.appendChild(pill("unknown", match.category.replace(/_/g, " ")));
    head.appendChild(node("span", "match__meta",
      "weight " + match.weight + " (" + match.severity + ") · "
      + match.occurrences + (match.occurrences === 1 ? " occurrence" : " occurrences")
      + (match.occurrences > match.counted_occurrences
        ? ", " + match.counted_occurrences + " counted" : "")));
    item.appendChild(head);
    (match.locations || []).forEach(function (location) {
      var excerpt = node("p", "match__excerpt", location.excerpt);
      excerpt.title = "Line " + location.line + ", character offset " + location.offset;
      item.appendChild(excerpt);
    });
    return item;
  }

  /* ---------------------------------------------------------------- panel */

  function openPanel(title) {
    state.panelFocus = document.activeElement;
    clear(el.panelBody);
    el.panelTitle.textContent = title;
    el.panel.hidden = false;
    el.panelClose.focus();
    return el.panelBody;
  }

  function closePanel() {
    el.panel.hidden = true;
    clear(el.panelBody);
    if (state.panelFocus && state.panelFocus.focus) state.panelFocus.focus();
  }

  function panelSection(parent, title) {
    var section = node("div", "panel__section");
    if (title) section.appendChild(node("h4", "", title));
    parent.appendChild(section);
    return section;
  }

  function openFilePanel(file) {
    var body = openPanel(file.filename || "Resource detail");

    var urlSection = panelSection(body, "URL (not linked, on purpose)");
    urlSection.appendChild(node("div", "panel__url", file.url || "Not recorded"));
    var actions = node("div", "panel__actions");
    if (file.url) actions.appendChild(copyButton(file.url, "Copy URL"));
    if (file.domain) {
      var domainButton = node("button", "btn btn--ghost btn--small", "Search this domain");
      domainButton.type = "button";
      domainButton.addEventListener("click", function () { pivot('page.domain:"' + file.domain + '"'); });
      actions.appendChild(domainButton);
    }
    urlSection.appendChild(actions);

    var facts = panelSection(body, "Network");
    var kv = node("dl", "kv");
    [
      ["Status", typeof file.status === "number" ? file.status + (file.status_text ? " " + file.status_text : "") : "No response"],
      ["Content type", file.mime_type || "—"],
      ["Resource type", file.resource_type || "—"],
      ["Method", file.method || "—"],
      ["Size", bytes(file.size_bytes)],
      ["Protocol", file.protocol || "—"],
      ["IP", file.ip || "—"],
      ["Country", file.country || file.country_code || "—"],
      ["Network", [file.asn, file.asn_name].filter(Boolean).join(" ") || "—"],
      ["Classified as", (file.service ? file.service + " · " : "") + file.category_label],
      ["Relationship", file.is_first_party ? "Apex domain of the scanned site" : "Third party"],
      ["Initiated by", file.initiator || "—"],
      ["TLS state", file.security_state || "—"]
    ].forEach(function (pair) {
      var wrap = document.createElement("div");
      wrap.appendChild(node("dt", "", pair[0]));
      wrap.appendChild(node("dd", "", pair[1]));
      kv.appendChild(wrap);
    });
    facts.appendChild(kv);

    if (file.failed) {
      var failure = panelSection(body, "Failure");
      failure.appendChild(node("p", "disclaimer", file.error || "The request failed."));
    }

    var hashSection = panelSection(body, "Hashes");
    hashSection.appendChild(hashCell(file));
    if (file.hashes && file.hashes.length) {
      hashSection.appendChild(node("p", "acard__note",
        "Click a hash to find other scans that fetched the same bytes. urlscan stores a SHA-256 of "
        + "each response body; SHA-1 and MD5 appear only when its download processor recorded them."));
    }

    var headerSection = panelSection(body, "Response headers");
    if (file.headers && file.headers.length) {
      headerSection.appendChild(headerTable(file.headers));
    } else {
      headerSection.appendChild(node("p", "acard__note", "No response headers were recorded."));
    }

    if (file.request_headers && file.request_headers.length) {
      var requestSection = panelSection(body, "Request headers");
      requestSection.appendChild(headerTable(file.request_headers));
    }

    var snippet = panelSection(body, "Content snippet");
    var summary = state.data.summary;
    var isMainDocument = file.url && summary.url && file.url === summary.url;
    if (isMainDocument && state.analysis && state.analysis.text && state.analysis.text.excerpt) {
      snippet.appendChild(node("pre", "excerpt-box", state.analysis.text.excerpt.slice(0, 4000)));
      snippet.appendChild(node("p", "acard__note",
        "Visible text extracted from the DOM urlscan stored for this scan."));
    } else if (isMainDocument) {
      snippet.appendChild(node("p", "acard__note",
        "Run \"Analyze page content\" to pull the stored DOM; its text will appear here."));
    } else {
      snippet.appendChild(node("p", "acard__note",
        "urlscan's result API does not return response bodies, so there is no snippet for this "
        + "resource. Only the main document's text is available, through the stored DOM."));
    }
  }

  function headerTable(headers) {
    var table = node("table", "headers");
    var body = document.createElement("tbody");
    headers.forEach(function (header) {
      var row = document.createElement("tr");
      row.appendChild(node("th", "", header.name));
      row.appendChild(node("td", "", header.value));
      body.appendChild(row);
    });
    table.appendChild(body);
    return table;
  }

  function openHashPanel(hash, file) {
    var body = openPanel(hash.algorithm.toUpperCase() + " · " + truncate(hash.value, 20));

    var section = panelSection(body, "Hash");
    section.appendChild(node("div", "panel__url", hash.value));
    var actions = node("div", "panel__actions");
    actions.appendChild(copyButton(hash.value, "Copy hash"));
    var searchButton = node("button", "btn btn--primary btn--small", "Search this hash in the dashboard");
    searchButton.type = "button";
    searchButton.addEventListener("click", function () { pivot("hash:" + hash.value); });
    actions.appendChild(searchButton);
    section.appendChild(actions);
    if (file) {
      section.appendChild(node("p", "acard__note",
        "From " + (file.filename || "this resource") + (file.domain ? " on " + file.domain : "") + "."));
    }

    var lookups = panelSection(body, "External lookups");
    var lookupRow = node("div", "panel__actions");
    [
      ["VirusTotal", "https://www.virustotal.com/gui/file/" + encodeURIComponent(hash.value)],
      ["MalwareBazaar", "https://bazaar.abuse.ch/browse.php?search=" + encodeURIComponent(hash.algorithm + ":" + hash.value)]
    ].forEach(function (pair) {
      var link = node("a", "btn btn--ghost btn--small", pair[0]);
      link.href = pair[1];
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      lookupRow.appendChild(link);
    });
    lookups.appendChild(lookupRow);
    lookups.appendChild(node("p", "acard__note",
      "This dashboard does not query malware databases itself, so it never claims a file is malicious. "
      + "These links open a third-party lookup in a new tab; a hash absent from them is not evidence "
      + "the file is safe."));

    var results = panelSection(body, "Other scans that fetched these bytes");
    var loading = node("p", "acard__note", "Searching the urlscan corpus for hash:" + truncate(hash.value, 16) + " …");
    results.appendChild(loading);

    request("/api/search", { q: "hash:" + hash.value, size: 25, resolve_dns: "false" })
      .then(function (payload) {
        loading.remove();
        var rows = payload.results || [];
        state.hashSeen[hash.value] = (payload.meta && typeof payload.meta.total === "number")
          ? payload.meta.total
          : rows.length;

        if (!rows.length) {
          results.appendChild(node("p", "acard__note",
            "No other scan in the urlscan corpus recorded this hash. That usually means the file is "
            + "unique to this site, or was not indexed."));
          renderFiles();
          return;
        }

        var meta = payload.meta || {};
        results.appendChild(node("p", "acard__note",
          (meta.total_is_exact === false ? "More than " : "")
          + fmt(typeof meta.total === "number" ? meta.total : rows.length)
          + " scans fetched this file. Showing " + fmt(rows.length) + ", newest first."));

        var wrap = node("div", "atable-wrap");
        var table = node("table", "atable");
        var head = document.createElement("thead");
        var headRow = document.createElement("tr");
        ["Date", "Domain", "URL", "Status", ""].forEach(function (label) {
          headRow.appendChild(node("th", "", label));
        });
        head.appendChild(headRow);
        table.appendChild(head);

        var tbody = document.createElement("tbody");
        rows.forEach(function (row) {
          var tr = document.createElement("tr");
          tr.appendChild(node("td", "", shortDate(row.time)));

          var domainCell = document.createElement("td");
          if (row.domain) {
            var domainButton = node("button", "link-btn", row.domain);
            domainButton.type = "button";
            domainButton.title = "Search the main dashboard for this domain";
            domainButton.addEventListener("click", function () { pivot('page.domain:"' + row.domain + '"'); });
            domainCell.appendChild(domainButton);
          } else {
            domainCell.appendChild(node("span", "", "—"));
          }
          tr.appendChild(domainCell);

          var urlCell = node("td", "mono", truncate(row.scanned_url || "—", 70));
          urlCell.title = row.scanned_url || "";
          tr.appendChild(urlCell);

          var statusTd = document.createElement("td");
          statusTd.appendChild(statusCell(typeof row.status === "number" ? row.status : null));
          tr.appendChild(statusTd);

          var actionCell = document.createElement("td");
          if (row.uuid) {
            var view = node("button", "btn btn--ghost btn--small", "View details");
            view.type = "button";
            view.addEventListener("click", function () {
              closePanel();
              open(row.uuid);
            });
            actionCell.appendChild(view);
          }
          tr.appendChild(actionCell);
          tbody.appendChild(tr);
        });
        table.appendChild(tbody);
        wrap.appendChild(table);
        results.appendChild(wrap);

        /* Re-render the file table so the badge now carries its prevalence count. */
        renderFiles();
      })
      .catch(function (error) {
        loading.remove();
        results.appendChild(node("p", "disclaimer", error.message || "The hash search failed."));
      });
  }

  /* ----------------------------------------------------------------- open */

  function buildShell() {
    if (state.ready) return;

    el.root = document.getElementById("analyzer");
    el.back = document.getElementById("an-back");
    el.uuidInput = document.getElementById("an-uuid");
    el.pull = document.getElementById("an-pull");
    el.chipHolder = document.getElementById("an-verdict-chip");
    el.report = document.getElementById("an-report");
    el.loading = document.getElementById("an-loading");
    el.loadingLabel = document.getElementById("an-loading-label");
    el.alert = document.getElementById("an-alert");
    el.alertMsg = document.getElementById("an-alert-msg");
    el.alertClose = document.getElementById("an-alert-close");
    el.intro = document.getElementById("an-intro");
    el.titleBlock = document.getElementById("an-title");
    el.pageTitle = document.getElementById("an-page-title");
    el.pageUrl = document.getElementById("an-page-url");
    el.body = document.getElementById("an-body");
    el.panel = document.getElementById("an-panel");
    el.panelTitle = document.getElementById("an-panel-title");
    el.panelBody = document.getElementById("an-panel-body");
    el.panelClose = document.getElementById("an-panel-close");

    el.back.addEventListener("click", close);
    el.alertClose.addEventListener("click", clearError);
    el.pull.addEventListener("click", function () {
      var value = (el.uuidInput.value || "").trim();
      if (!UUID_SHAPE.test(value)) {
        showError("Enter a urlscan.io scan ID — 36 characters, like "
          + "01234567-89ab-cdef-0123-456789abcdef.");
        el.uuidInput.focus();
        return;
      }
      load(value, true);
    });
    el.uuidInput.addEventListener("keydown", function (event) {
      if (event.key === "Enter") { event.preventDefault(); el.pull.click(); }
    });
    el.panelClose.addEventListener("click", closePanel);
    el.panel.addEventListener("click", function (event) {
      if (event.target === el.panel) closePanel();
    });
    document.addEventListener("keydown", function (event) {
      if (event.key !== "Escape") return;
      if (!el.panel.hidden) { closePanel(); return; }
      if (!el.root.hidden) close();
    });

    state.ready = true;
  }

  function buildCards() {
    clear(el.body);

    var summaryCard = card("card-summary", "Result summary", state.data.summary.domain || "");
    renderSummary(summaryCard._body);
    el.body.appendChild(summaryCard);

    var verdictCard = card("card-verdicts", "Security engines and threat score",
      state.data.verdicts.threat_score + "/100");
    renderVerdicts(verdictCard._body);
    el.body.appendChild(verdictCard);

    var contentCard = card("card-content", "Content analysis", "keyword risk scoring");
    el.contentBody = contentCard._body;
    renderContentAnalysis(contentCard._body);
    el.body.appendChild(contentCard);

    var filesCard = card("card-files", "Files and resources", "");
    el.fileCount = filesCard._count;
    buildFileTools(filesCard._body);
    el.body.appendChild(filesCard);

    var domainCard = card("card-domains", "Domains and connections",
      fmt((state.data.domains || []).length) + " domains");
    renderDomains(domainCard._body);
    el.body.appendChild(domainCard);

    renderFiles();
  }

  function buildFileTools(container) {
    var tools = node("div", "acard__tools");

    var filterKnob = node("div", "knob knob--grow");
    filterKnob.appendChild(node("label", "", "Filter these resources"));
    el.fileFilter = document.createElement("input");
    el.fileFilter.type = "search";
    el.fileFilter.className = "field";
    el.fileFilter.placeholder = "filename, domain, type, hash…";
    el.fileFilter.spellcheck = false;
    el.fileFilter.addEventListener("input", renderFiles);
    filterKnob.appendChild(el.fileFilter);
    tools.appendChild(filterKnob);

    var sortKnob = node("div", "knob");
    sortKnob.appendChild(node("label", "", "Order"));
    el.fileSort = document.createElement("select");
    el.fileSort.className = "field";
    [
      ["index:asc", "Request order"],
      ["size:desc", "Largest first"],
      ["size:asc", "Smallest first"],
      ["status:desc", "Worst status first"],
      ["domain:asc", "Domain A–Z"],
      ["type:asc", "Content type"],
      ["hash:asc", "Hash (groups identical files)"]
    ].forEach(function (pair) {
      var option = document.createElement("option");
      option.value = pair[0];
      option.textContent = pair[1];
      el.fileSort.appendChild(option);
    });
    el.fileSort.addEventListener("change", renderFiles);
    sortKnob.appendChild(el.fileSort);
    tools.appendChild(sortKnob);

    var apexKnob = node("div", "knob");
    apexKnob.appendChild(node("span", "knob__label", "Scope"));
    el.apexToggle = node("button", "btn btn--ghost btn--small", "Show only apex domain files");
    el.apexToggle.type = "button";
    el.apexToggle.setAttribute("aria-pressed", "false");
    el.apexToggle.addEventListener("click", function () {
      var on = el.apexToggle.getAttribute("aria-pressed") !== "true";
      el.apexToggle.setAttribute("aria-pressed", String(on));
      el.apexToggle.textContent = on ? "Showing apex domain only" : "Show only apex domain files";
      renderFiles();
    });
    apexKnob.appendChild(el.apexToggle);
    tools.appendChild(apexKnob);

    container.appendChild(tools);

    el.filesTable = node("div");
    container.appendChild(el.filesTable);

    el.fileNote = node("p", "acard__note");
    container.appendChild(el.fileNote);
  }

  function paintHeader() {
    var summary = state.data.summary;
    var verdicts = state.data.verdicts;

    el.pageTitle.textContent = summary.title || summary.domain || "Scan result";
    el.pageUrl.textContent = summary.url || summary.submitted_url || "";
    el.titleBlock.hidden = false;
    el.intro.hidden = true;
    el.body.hidden = false;

    clear(el.chipHolder);
    var labels = { clean: "No verdict", low: "Low", suspicious: "Suspicious", malicious: "Malicious" };
    el.chipHolder.appendChild(chip(verdicts.band, labels[verdicts.band] || verdicts.band));

    if (summary.report_url) {
      el.report.href = summary.report_url;
      el.report.hidden = false;
    } else {
      el.report.hidden = true;
    }
  }

  function load(uuid, force) {
    if (state.busy) return;
    uuid = String(uuid || "").trim().toLowerCase();
    if (!UUID_SHAPE.test(uuid)) {
      showError("That is not a urlscan.io scan ID.");
      return;
    }

    clearError();
    el.uuidInput.value = uuid;
    state.uuid = uuid;
    state.analysis = cacheRead(ANALYSIS_PREFIX, uuid);

    var cached = force ? null : cacheRead(RESULT_PREFIX, uuid);
    if (cached) {
      state.data = cached;
      paintHeader();
      buildCards();
      return;
    }

    setBusy(true, "Pulling the result for " + uuid.slice(0, 8) + "… from urlscan.io");
    request("/api/result/" + uuid, {})
      .then(function (body) {
        state.data = body;
        cacheWrite(RESULT_PREFIX, uuid, body);
        paintHeader();
        buildCards();
        el.root.scrollTop = 0;
      })
      .catch(function (error) {
        showError(error.message || "Could not pull that result.");
        if (!state.data) {
          el.intro.hidden = false;
          el.body.hidden = true;
          el.titleBlock.hidden = true;
        }
      })
      .finally(function () { setBusy(false); });
  }

  function open(uuid) {
    buildShell();
    state.lastFocus = document.activeElement;
    el.root.hidden = false;
    document.body.style.overflow = "hidden";

    if (uuid) {
      if (uuid !== state.uuid || !state.data) load(uuid, false);
    } else {
      el.uuidInput.focus();
    }
  }

  function close() {
    if (!state.ready) return;
    if (!el.panel.hidden) closePanel();
    el.root.hidden = true;
    document.body.style.overflow = "";
    if (state.lastFocus && state.lastFocus.focus) state.lastFocus.focus();
  }

  function init(options) {
    options = options || {};
    hooks.getKey = options.getKey || function () {
      var field = document.getElementById("api-key");
      return field ? (field.value || "").trim() : "";
    };
    hooks.onPivot = options.onPivot || null;
    buildShell();
  }

  return {
    init: init,
    open: open,
    close: close,
    clearCache: clearCache,
    isOpen: function () { return state.ready && !el.root.hidden; }
  };
})();
