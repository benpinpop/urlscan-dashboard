/* Contact sheet — urlscan.io search dashboard.
 *
 * All network calls go to this app's own /api/* endpoints, which add the
 * API-Key header server-side. The key never appears in a URL.
 */

(function () {
  "use strict";

  var STORAGE_KEY = "urlscan-dashboard.apikey";

  var el = {
    key: document.getElementById("api-key"),
    keyPanel: document.getElementById("key-panel"),
    keyReveal: document.getElementById("key-reveal"),
    keyForget: document.getElementById("key-forget"),
    keyRemember: document.getElementById("key-remember"),
    query: document.getElementById("query"),
    size: document.getElementById("size"),
    sort: document.getElementById("sort"),
    filter: document.getElementById("filter"),
    collapseDomain: document.getElementById("collapse-domain"),
    resolveDns: document.getElementById("resolve-dns"),
    toggleDetails: document.getElementById("toggle-details"),
    toggleDead: document.getElementById("toggle-dead"),
    dnsStatusControl: document.getElementById("dns-status-control"),
      toggleExport: document.getElementById("toggle-export"),
      exportMenu: document.getElementById("export-menu"),
      exportDead: document.getElementById("export-dead"),
      exportLive: document.getElementById("export-live"),
      exportDedupe: document.getElementById("export-dedupe"),
      exportStatusFilters: document.getElementById("export-status-filters"),
      exportType: document.getElementById("export-type"),
      exportDownload: document.getElementById("export-download"),
    run: document.getElementById("run"),
    quota: document.getElementById("quota"),
    sheet: document.getElementById("sheet"),
    empty: document.getElementById("empty"),
    status: document.getElementById("status-line"),
    alert: document.getElementById("alert"),
    alertMsg: document.getElementById("alert-msg"),
    alertClose: document.getElementById("alert-close"),
    loading: document.getElementById("loading"),
    more: document.getElementById("more"),
    loadMore: document.getElementById("load-more"),
    moreNote: document.getElementById("more-note"),
    lightbox: document.getElementById("lightbox"),
    lightboxImg: document.getElementById("lightbox-img"),
    lightboxTitle: document.getElementById("lightbox-title"),
    lightboxFacts: document.getElementById("lightbox-facts"),
    lightboxClose: document.getElementById("lightbox-close"),
    tpl: document.getElementById("frame-tpl"),
    exampleList: document.getElementById("example-list")
  };

  var state = {
    results: [],
    cursor: null,
    query: "",
    size: 100,
    total: null,
    totalExact: true,
    hasMore: false,
    dnsAvailable: false,
    searchMs: null,
    dnsMs: null,
    busy: false,
    lastFocus: null
  };

  /* ---------------------------------------------------------------- utils */

  function fmt(n) {
    return typeof n === "number" ? n.toLocaleString() : String(n);
  }

  function showAlert(message) {
    el.alertMsg.textContent = message;
    el.alert.hidden = false;
  }

  function clearAlert() {
    el.alert.hidden = true;
    el.alertMsg.textContent = "";
  }

  function setBusy(busy) {
    state.busy = busy;
    el.loading.hidden = !busy;
    el.run.disabled = busy;
    el.loadMore.disabled = busy;
    el.run.textContent = busy ? "Searching…" : "Search";
  }

  function syncDnsUi() {
    var available = state.dnsAvailable;
    el.dnsStatusControl.hidden = !available;
    el.exportStatusFilters.hidden = !available;
    el.toggleDead.hidden = !available;
    if (!available) {
      el.toggleDead.setAttribute("aria-pressed", "false");
      el.toggleDead.textContent = "Hide dead sites";
    }
  }

  function formatTime(iso) {
    if (!iso) return "Not recorded";
    var d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    return d.toLocaleString(undefined, {
      year: "numeric", month: "short", day: "2-digit",
      hour: "2-digit", minute: "2-digit"
    });
  }

  function renderExamples() {
    var examples = Array.isArray(window.URLSCAN_EXAMPLES) ? window.URLSCAN_EXAMPLES : [];
    examples.forEach(function (query) {
      var item = document.createElement("li");
      var button = document.createElement("button");
      button.type = "button";
      button.className = "example";
      button.dataset.q = query;
      button.textContent = query;
      item.appendChild(button);
      el.exampleList.appendChild(item);
    });
  }

  /* ------------------------------------------------------------- api key */

  function currentKey() {
    return (el.key.value || "").trim();
  }

  function syncKeyState() {
    el.keyPanel.classList.toggle("is-set", currentKey().length > 0);
  }

  function loadStoredKey() {
    var stored = null;
    try {
      stored = window.localStorage.getItem(STORAGE_KEY);
    } catch (e) {
      stored = null; /* storage blocked; fall through to manual entry */
    }
    if (stored) {
      el.key.value = stored;
      el.keyRemember.checked = true;
    }
    syncKeyState();
  }

  function persistKey() {
    try {
      if (el.keyRemember.checked && currentKey()) {
        window.localStorage.setItem(STORAGE_KEY, currentKey());
      } else {
        window.localStorage.removeItem(STORAGE_KEY);
      }
    } catch (e) {
      showAlert("This browser blocked local storage, so the key will not be kept between visits.");
      el.keyRemember.checked = false;
    }
  }

  /* -------------------------------------------------------------- request */

  function request(path, params) {
    var url = new URL(path, window.location.origin);
    Object.keys(params || {}).forEach(function (k) {
      if (params[k] !== null && params[k] !== undefined && params[k] !== "") {
        url.searchParams.set(k, params[k]);
      }
    });

    var headers = { Accept: "application/json" };
    if (currentKey()) headers["X-URLScan-Key"] = currentKey();

    return fetch(url.toString(), { headers: headers, cache: "no-store" })
      .then(function (response) {
        return response.json().catch(function () {
          throw new Error("The server returned a response this page could not read.");
        }).then(function (body) {
          if (!response.ok || body.ok === false) {
            var err = new Error((body.error && body.error.message) || "Request failed.");
            err.code = body.error && body.error.code;
            throw err;
          }
          return body;
        });
      });
  }

  /* -------------------------------------------------------------- render */

  function statusText(result) {
    var s = result.status;
    if (s === null || s === undefined || s === "") return { text: "Not recorded", cls: "flag--warn" };
    var n = parseInt(s, 10);
    if (isNaN(n)) return { text: String(s), cls: "" };
    if (n >= 400) return { text: String(n), cls: "flag--bad" };
    if (n >= 300) return { text: String(n), cls: "flag--warn" };
    return { text: String(n), cls: "flag--ok" };
  }

  function tlsText(result) {
    var days = result.tls_valid_days;
    var issuer = result.tls_issuer;
    if (days === null || days === undefined) {
      return { text: issuer || "No certificate recorded", cls: issuer ? "" : "flag--warn" };
    }
    if (days < 0) {
      return { text: "Expired " + Math.abs(days) + " days ago", cls: "flag--bad" };
    }
    var label = days + " days left";
    if (issuer) label = issuer + ", " + days + " days left";
    return { text: label, cls: days <= 14 ? "flag--warn" : "" };
  }

  function domainAgeText(ageDays) {
    var age = Number(ageDays);
    if (!isFinite(age) || age < 0) return "Age unknown";

    var totalHours = Math.floor(age * 24);
    var days = Math.floor(totalHours / 24);
    var hours = totalHours % 24;
    if (days >= 365) {
      var years = Math.floor(days / 365);
      var remainingMonths = Math.floor((days % 365) / 30);
      return years + "y" + (remainingMonths ? " " + remainingMonths + "mo" : "");
    }
    if (days >= 30) {
      var months = Math.floor(days / 30);
      return months + "mo";
    }
    if (days) return days + "d" + (hours ? " " + hours + "h" : "");
    return hours + "h";
  }

  function isIpAddress(value) {
    var text = String(value || "").trim();
    if (text.indexOf(":") !== -1) return true;
    return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(text);
  }

  function buildFrame(result) {
    var node = el.tpl.content.firstElementChild.cloneNode(true);
    var shot = node.querySelector(".shot");
    var img = node.querySelector(".shot__img");
    var domain = node.querySelector(".frame__domain");
    var dnsStatus = node.querySelector(".dns-status");
    var domainAge = node.querySelector(".domain-age");

    node.querySelector(".frame__no").textContent = String(result.index).padStart(3, "0");

    if (result.screenshot) {
      img.src = result.screenshot;
      img.alt = "Screenshot of " + (result.domain || "this page");
      img.addEventListener("error", function () {
        shot.classList.add("is-blank");
      });
      shot.addEventListener("click", function () { openLightbox(result); });
    } else {
      shot.classList.add("is-blank");
      shot.disabled = true;
    }

    domain.textContent = result.domain || "Unknown domain";
    dnsStatus.hidden = !state.dnsAvailable;
    if (state.dnsAvailable) {
      dnsStatus.textContent = result.dns_status ? "Live" : "Dead";
      dnsStatus.classList.add(result.dns_status ? "dns-status--live" : "dns-status--dead");
      dnsStatus.setAttribute("aria-label", result.dns_status ? "Domain is live" : "Domain is dead");
    }
    domainAge.hidden = isIpAddress(result.domain);
    domainAge.textContent = domainAgeText(result.domain_age_days);
    domainAge.title = "Domain age at the time of the scan";
    if (result.result_url) {
      domain.href = result.result_url;
      domain.title = "Open the urlscan.io report for this scan";
    } else {
      domain.removeAttribute("href");
    }

    var ip = node.querySelector(".fact--ip dd");
    ip.textContent = result.ip || "Not recorded";
    if (result.country) {
      var cc = document.createElement("span");
      cc.className = "cc";
      cc.textContent = result.country.toUpperCase();
      ip.appendChild(cc);
    }

    var status = statusText(result);
    var statusEl = node.querySelector(".fact--status dd");
    statusEl.textContent = status.text;
    if (status.cls) statusEl.classList.add(status.cls);

    var tls = tlsText(result);
    var tlsEl = node.querySelector(".fact--tls dd");
    tlsEl.textContent = tls.text;
    if (tls.cls) tlsEl.classList.add(tls.cls);

    node.querySelector(".fact--time dd").textContent = formatTime(result.time);

    node.dataset.haystack = [
      result.domain, result.ip, result.asn, result.asn_name,
      result.country, result.server, result.scanned_url, result.tls_issuer
    ].filter(Boolean).join(" ").toLowerCase();

    return node;
  }

  function sortResults(list) {
    var parts = el.sort.value.split(":");
    var field = parts[0];
    var dir = parts[1] === "asc" ? 1 : -1;

    var pick = {
      time: function (r) { return r.time ? Date.parse(r.time) || 0 : 0; },
      domain: function (r) { return (r.domain || "").toLowerCase(); },
      ip: function (r) { return ipKey(r.ip); },
      country: function (r) { return (r.country || "zz").toLowerCase(); },
      status: function (r) { return parseInt(r.status, 10) || 0; },
      domain_age: function (r) {
        var age = Number(r.domain_age_days);
        return isFinite(age) && age >= 0
          ? age
          : (dir === 1 ? Number.MAX_SAFE_INTEGER : Number.MIN_SAFE_INTEGER);
      },
      tls: function (r) {
        return r.tls_valid_days === null || r.tls_valid_days === undefined
          ? Number.MAX_SAFE_INTEGER : r.tls_valid_days;
      }
    }[field];

    return list.slice().sort(function (a, b) {
      var x = pick(a), y = pick(b);
      if (x < y) return -1 * dir;
      if (x > y) return 1 * dir;
      return 0;
    });
  }

  function collapseToLatest(list) {
    var latest = new Map();

    list.forEach(function (result) {
      var domain = (result.domain || "").trim().toLowerCase().replace(/^www\./, "");
      var key = domain || "__missing_domain_" + result.index;
      var current = latest.get(key);
      var resultTime = result.time ? Date.parse(result.time) || 0 : 0;
      var currentTime = current && current.time ? Date.parse(current.time) || 0 : 0;

      if (!current || resultTime > currentTime) latest.set(key, result);
    });

    return Array.from(latest.values());
  }

  /* Sort IPv4 numerically so 10.0.0.9 lands before 10.0.0.10. */
  function ipKey(ip) {
    if (!ip) return "";
    var octets = ip.split(".");
    if (octets.length === 4 && octets.every(function (o) { return /^\d{1,3}$/.test(o); })) {
      return octets.map(function (o) { return o.padStart(3, "0"); }).join(".");
    }
    return ip.toLowerCase();
  }

  function render() {
    var displayResults = el.collapseDomain.checked
      ? collapseToLatest(state.results)
      : state.results;
    if (state.dnsAvailable && el.toggleDead.getAttribute("aria-pressed") === "true") {
      displayResults = displayResults.filter(function (result) { return result.dns_status !== false; });
    }
    var ordered = sortResults(displayResults);
    state.displayedCount = ordered.length;
    var fragment = document.createDocumentFragment();
    ordered.forEach(function (result) { fragment.appendChild(buildFrame(result)); });

    el.sheet.textContent = "";
    el.sheet.appendChild(fragment);

    el.empty.hidden = state.results.length > 0;
    updateStatus();
    applyFilter();
  }

  function applyFilter() {
    var term = (el.filter.value || "").trim().toLowerCase();
    var shown = 0;
    Array.prototype.forEach.call(el.sheet.children, function (frame) {
      var match = !term || frame.dataset.haystack.indexOf(term) !== -1;
      frame.classList.toggle("is-hidden", !match);
      if (match) shown += 1;
    });

    if (!term) {
      updateStatus();
      return;
    }

    el.status.textContent = "";
    el.status.append(
      document.createTextNode("Showing "),
      strong(fmt(shown)),
      document.createTextNode(" of " + fmt(state.displayedCount) + " displayed frames.")
    );
  }

  function strong(text) {
    var s = document.createElement("strong");
    s.textContent = text;
    return s;
  }

    function csvCell(value) {
      var text = value === null || value === undefined ? "" : String(value);
      return '"' + text.replace(/"/g, '""') + '"';
    }

    function exportResults() {
      var includeDead = !state.dnsAvailable || el.exportDead.checked;
      var includeLive = !state.dnsAvailable || el.exportLive.checked;
      if (state.dnsAvailable && !includeDead && !includeLive) {
        showAlert("Select Dead sites, Live sites, or both before exporting.");
        return;
      }
      if (!state.results.length) {
        showAlert("Run a search before exporting sites.");
        return;
      }

      var results = state.results.slice();
      if (el.exportDedupe.checked) results = collapseToLatest(results);
      results = results.filter(function (result) {
        return result.dns_status ? includeLive : includeDead;
      });

      if (!results.length) {
        showAlert("No loaded sites match the selected DNS statuses.");
        return;
      }

      var extension = el.exportType.value;
      var content;
      if (extension === "csv") {
        var rows = state.dnsAvailable
          ? [["Domain", "DNS status", "URLScan IP", "Live IP", "Scanned", "Report URL"]]
          : [["Domain", "URLScan IP", "Scanned", "Report URL"]];
        results.forEach(function (result) {
          rows.push(state.dnsAvailable
            ? [result.domain || "", result.dns_status ? "Live" : "Dead", result.ip || "", result.live_ip || "", result.time || "", result.result_url || ""]
            : [result.domain || "", result.ip || "", result.time || "", result.result_url || ""]);
        });
        content = rows.map(function (row) { return row.map(csvCell).join(","); }).join("\r\n") + "\r\n";
      } else {
        content = results.map(function (result) { return result.domain || "Unknown domain"; }).join("\r\n") + "\r\n";
      }

      var blob = new Blob([content], { type: extension === "csv" ? "text/csv;charset=utf-8" : "text/plain;charset=utf-8" });
      var url = URL.createObjectURL(blob);
      var link = document.createElement("a");
      link.href = url;
      link.download = "urlscan-sites." + extension;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      el.exportMenu.hidden = true;
      el.toggleExport.setAttribute("aria-expanded", "false");
    }

  function updateStatus() {
    if (!state.results.length) {
      el.status.textContent = "Nothing on the sheet yet.";
      el.more.hidden = true;
      return;
    }

    el.status.textContent = "";
    if (state.displayedCount !== state.results.length) {
      el.status.append(
        strong(fmt(state.displayedCount)),
        document.createTextNode(" displayed from "),
        strong(fmt(state.results.length)),
        document.createTextNode(" loaded frames")
      );
    } else {
      el.status.append(strong(fmt(state.results.length)), document.createTextNode(" frames loaded"));
    }

    if (typeof state.total === "number") {
      var totalLabel = state.totalExact
        ? " of " + fmt(state.total) + " matches"
        : " of more than " + fmt(state.total) + " matches";
      el.status.append(document.createTextNode(totalLabel));
    }
    el.status.append(document.createTextNode("."));

    if (typeof state.searchMs === "number" && state.dnsAvailable && typeof state.dnsMs === "number") {
      el.status.append(
        document.createTextNode(" Search took " + fmt(state.searchMs) + " ms; DNS took " + fmt(state.dnsMs) + " ms.")
      );
    } else if (typeof state.searchMs === "number") {
      el.status.append(document.createTextNode(" Search took " + fmt(state.searchMs) + " ms."));
    }

    if (state.results.length >= 2000) {
      el.status.append(document.createTextNode(
        " That many screenshots will scroll slowly — narrow the query or use a smaller page size."
      ));
    }

    el.more.hidden = !(state.hasMore && state.cursor);
    el.moreNote.textContent = state.hasMore
      ? "urlscan pages with a cursor, so the next page continues from the oldest frame above."
      : "";
  }

  /* -------------------------------------------------------------- search */

  function runSearch(append) {
    if (state.busy) return;

    var query = (el.query.value || "").trim();
    if (!query) {
      showAlert("Enter a query first. Try page.domain:example.com.");
      el.query.focus();
      return;
    }

    clearAlert();
    setBusy(true);

    var params = {
      q: query,
      size: el.size.value,
      resolve_dns: el.resolveDns.checked ? "true" : "false"
    };
    if (append && state.cursor) params.search_after = state.cursor;

    request("/api/search", params)
      .then(function (body) {
        var incoming = body.results || [];

        if (append) {
          var offset = state.results.length;
          incoming.forEach(function (r) { r.index = offset + r.index; });
          state.results = state.results.concat(incoming);
        } else {
          state.results = incoming;
          window.scrollTo({ top: 0, behavior: "smooth" });
        }

        state.query = body.meta.query;
        state.size = body.meta.size;
        state.total = body.meta.total;
        state.totalExact = body.meta.total_is_exact;
        state.hasMore = body.meta.has_more;
        state.cursor = body.meta.next_cursor;
        state.dnsAvailable = body.meta.dns_enabled === true;
        state.searchMs = body.meta.search_ms;
        state.dnsMs = body.meta.dns_ms;
        syncDnsUi();

        render();

        if (!state.results.length) {
          showAlert("No scans match that query. Check the field names, or widen the search.");
        }
      })
      .catch(function (err) {
        showAlert(err.message || "The search failed.");
        if (err.code === "invalid_api_key" || err.code === "missing_api_key" || err.code === "malformed_api_key") {
          el.key.focus();
        }
      })
      .finally(function () { setBusy(false); });
  }

  function checkQuota() {
    clearAlert();
    request("/api/quotas", {})
      .then(function (body) {
        var search = body.search || {};
        var windows = ["minute", "hour", "day"].filter(function (w) { return search[w]; });
        if (!windows.length) {
          el.status.textContent = "urlscan did not report a search quota for this key.";
          return;
        }
        var text = windows.map(function (w) {
          var q = search[w];
          var left = (q.limit || 0) - (q.used || 0);
          return left + " of " + q.limit + " searches left this " + w;
        }).join(" — ");
        el.status.textContent = text + ".";
      })
      .catch(function (err) { showAlert(err.message); });
  }

  /* ------------------------------------------------------------ lightbox */

  function openLightbox(result) {
    state.lastFocus = document.activeElement;
    el.lightboxTitle.textContent = result.domain || "Scan detail";
    el.lightboxImg.src = result.screenshot;
    el.lightboxImg.alt = "Full screenshot of " + (result.domain || "this page");

    var facts = [
      ["IP contacted at scan time", result.ip || "Not recorded"],
      ["Reverse DNS", result.ptr || "None"],
      ["Network", [result.asn, result.asn_name].filter(Boolean).join(" ") || "Not recorded"],
      ["Country", result.country || "Not recorded"],
      ["HTTP status", statusText(result).text],
      ["Server header", result.server || "Not sent"],
      ["Certificate", tlsText(result).text],
      ["Scanned", formatTime(result.time)],
      ["Visibility", result.visibility || "Not recorded"],
      ["URL scanned (not linked)", result.scanned_url || "Not recorded"]
    ];

    el.lightboxFacts.textContent = "";
    facts.forEach(function (pair) {
      var wrap = document.createElement("div");
      var dt = document.createElement("dt");
      dt.textContent = pair[0];
      var dd = document.createElement("dd");
      dd.textContent = pair[1];
      if (pair[0].indexOf("URL scanned") === 0) dd.className = "mono";
      wrap.append(dt, dd);
      el.lightboxFacts.appendChild(wrap);
    });

    if (result.result_url) {
      var wrap = document.createElement("div");
      var dt = document.createElement("dt");
      dt.textContent = "Full report";
      var dd = document.createElement("dd");
      var a = document.createElement("a");
      a.href = result.result_url;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      a.textContent = "Open on urlscan.io";
      dd.appendChild(a);
      wrap.append(dt, dd);
      el.lightboxFacts.appendChild(wrap);
    }

    el.lightbox.hidden = false;
    el.lightboxClose.focus();
  }

  function closeLightbox() {
    el.lightbox.hidden = true;
    el.lightboxImg.removeAttribute("src");
    if (state.lastFocus && state.lastFocus.focus) state.lastFocus.focus();
  }

  /* -------------------------------------------------------------- wiring */

  el.run.addEventListener("click", function () { runSearch(false); });
  el.loadMore.addEventListener("click", function () { runSearch(true); });
  el.quota.addEventListener("click", checkQuota);
  el.alertClose.addEventListener("click", clearAlert);
  el.sort.addEventListener("change", render);
  el.filter.addEventListener("input", applyFilter);
  el.collapseDomain.addEventListener("change", render);
  el.toggleDetails.addEventListener("click", function () {
    var minimal = el.sheet.classList.toggle("is-minimal");
    el.toggleDetails.textContent = minimal ? "Show details" : "Hide details";
    el.toggleDetails.setAttribute("aria-pressed", String(minimal));
  });
  el.toggleDead.addEventListener("click", function () {
    var hiding = el.toggleDead.getAttribute("aria-pressed") !== "true";
    el.toggleDead.setAttribute("aria-pressed", String(hiding));
    el.toggleDead.textContent = hiding ? "Show dead sites" : "Hide dead sites";
    render();
  });
  el.toggleExport.addEventListener("click", function () {
    var opening = el.exportMenu.hidden;
    el.exportMenu.hidden = !opening;
    el.toggleExport.setAttribute("aria-expanded", String(opening));
  });
  el.exportDownload.addEventListener("click", exportResults);

  el.query.addEventListener("keydown", function (event) {
    if (event.key === "Enter") { event.preventDefault(); runSearch(false); }
  });

  el.key.addEventListener("input", function () { syncKeyState(); persistKey(); });
  el.keyRemember.addEventListener("change", persistKey);

  el.keyReveal.addEventListener("click", function () {
    var showing = el.key.type === "text";
    el.key.type = showing ? "password" : "text";
    el.keyReveal.textContent = showing ? "Show" : "Hide";
    el.keyReveal.setAttribute("aria-pressed", String(!showing));
  });

  el.keyForget.addEventListener("click", function () {
    el.key.value = "";
    el.keyRemember.checked = false;
    try { window.localStorage.removeItem(STORAGE_KEY); } catch (e) { /* nothing to clear */ }
    syncKeyState();
    el.key.focus();
  });

  Array.prototype.forEach.call(document.querySelectorAll(".density__btn"), function (button) {
    button.addEventListener("click", function () {
      var cols = button.dataset.cols;
      el.sheet.classList.remove("cols-4", "cols-6", "cols-10");
      el.sheet.classList.add("cols-" + cols);
      document.querySelectorAll(".density__btn").forEach(function (b) {
        b.classList.toggle("is-on", b === button);
        b.setAttribute("aria-pressed", String(b === button));
      });
    });
  });

  renderExamples();
  document.querySelectorAll(".example").forEach(function (button) {
    button.addEventListener("click", function () {
      el.query.value = button.dataset.q;
      runSearch(false);
    });
  });

  el.lightboxClose.addEventListener("click", closeLightbox);
  el.lightbox.addEventListener("click", function (event) {
    if (event.target === el.lightbox) closeLightbox();
  });
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape" && !el.lightbox.hidden) closeLightbox();
  });

  loadStoredKey();
  syncDnsUi();
})();
