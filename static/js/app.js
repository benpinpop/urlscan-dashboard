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
    keyNote: document.getElementById("key-note"),
    query: document.getElementById("query"),
    size: document.getElementById("size"),
    sort: document.getElementById("sort"),
    filter: document.getElementById("filter"),
    group: document.getElementById("group-toggle"),
    bulk: document.getElementById("bulk"),
    collapseAll: document.getElementById("collapse-all"),
    expandAll: document.getElementById("expand-all"),
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
    frameTpl: document.getElementById("frame-tpl"),
    groupTpl: document.getElementById("group-tpl")
  };

  var state = {
    results: [],
    cursor: null,
    query: "",
    size: 100,
    total: null,
    totalExact: true,
    hasMore: false,
    busy: false,
    cols: 6,
    groupBy: false,
    groupCount: 0,
    collapsed: {},   // domain -> true, kept across re-renders
    lastFocus: null
  };

  /* ---------------------------------------------------------------- utils */

  function fmt(n) {
    return typeof n === "number" ? n.toLocaleString() : String(n);
  }

  function plural(n, one, many) {
    return fmt(n) + " " + (n === 1 ? one : many);
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

  function formatTime(iso) {
    if (!iso) return "Not recorded";
    var d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    return d.toLocaleString(undefined, {
      year: "numeric", month: "short", day: "2-digit",
      hour: "2-digit", minute: "2-digit"
    });
  }

  function formatDay(iso) {
    if (!iso) return "unknown";
    var d = new Date(iso);
    if (isNaN(d.getTime())) return "unknown";
    return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "2-digit" });
  }

  function strong(text) {
    var s = document.createElement("strong");
    s.textContent = text;
    return s;
  }

  /* ------------------------------------------------------------- api key */

  function currentKey() {
    return (el.key.value || "").trim();
  }

  function syncKeyState() {
    el.keyPanel.classList.toggle("is-set", currentKey().length > 0);
    el.keyNote.hidden = !el.keyRemember.checked;
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
    syncKeyState();
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

  /* ------------------------------------------------------------- signals */

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

  /* -------------------------------------------------------------- frames */

  function buildFrame(result) {
    var node = el.frameTpl.content.firstElementChild.cloneNode(true);
    var shot = node.querySelector(".shot");
    var img = node.querySelector(".shot__img");
    var domain = node.querySelector(".frame__domain");

    node.querySelector(".frame__no").textContent = String(result.index).padStart(3, "0");

    if (result.screenshot) {
      img.src = result.screenshot;
      img.alt = "Screenshot of " + (result.domain || "this page");
      img.addEventListener("error", function () { shot.classList.add("is-blank"); });
      shot.addEventListener("click", function () { openLightbox(result); });
    } else {
      shot.classList.add("is-blank");
      shot.disabled = true;
    }

    domain.textContent = result.domain || "Unknown domain";
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

  /* -------------------------------------------------------------- groups */

  function groupKey(result) {
    return result.domain || "Unknown domain";
  }

  /* Group in the order the sorted list produced, so the chosen sort still
     decides which domain appears first. */
  function groupResults(ordered) {
    var map = new Map();
    ordered.forEach(function (result) {
      var key = groupKey(result);
      if (!map.has(key)) map.set(key, []);
      map.get(key).push(result);
    });
    return map;
  }

  function chip(text, alert) {
    var span = document.createElement("span");
    span.className = alert ? "chip chip--alert" : "chip";
    span.textContent = text;
    return span;
  }

  function buildGroup(domain, items) {
    var node = el.groupTpl.content.firstElementChild.cloneNode(true);
    var bar = node.querySelector(".group__bar");
    var meta = node.querySelector(".group__meta");
    var grid = node.querySelector(".group__grid");

    node.dataset.domain = domain;
    node.querySelector(".group__name").textContent = domain;

    var ips = {};
    var failing = 0;
    var latest = null;
    items.forEach(function (r) {
      if (r.ip) ips[r.ip] = true;
      var code = parseInt(r.status, 10);
      if (!isNaN(code) && code >= 400) failing += 1;
      if (r.time && (!latest || r.time > latest)) latest = r.time;
    });

    meta.appendChild(chip(plural(items.length, "scan", "scans")));
    meta.appendChild(chip(plural(Object.keys(ips).length, "address", "addresses")));
    if (failing) meta.appendChild(chip(failing + " failing", true));
    meta.appendChild(chip("last seen " + formatDay(latest)));

    items.forEach(function (r) { grid.appendChild(buildFrame(r)); });

    var collapsed = !!state.collapsed[domain];
    node.classList.toggle("is-collapsed", collapsed);
    bar.setAttribute("aria-expanded", String(!collapsed));

    bar.addEventListener("click", function () {
      var nowCollapsed = !node.classList.contains("is-collapsed");
      node.classList.toggle("is-collapsed", nowCollapsed);
      bar.setAttribute("aria-expanded", String(!nowCollapsed));
      if (nowCollapsed) state.collapsed[domain] = true;
      else delete state.collapsed[domain];
    });

    return node;
  }

  function setAllCollapsed(collapsed) {
    Array.prototype.forEach.call(el.sheet.querySelectorAll(".group"), function (group) {
      var domain = group.dataset.domain;
      group.classList.toggle("is-collapsed", collapsed);
      group.querySelector(".group__bar").setAttribute("aria-expanded", String(!collapsed));
      if (collapsed) state.collapsed[domain] = true;
      else delete state.collapsed[domain];
    });
  }

  /* -------------------------------------------------------------- sorting */

  /* Sort IPv4 numerically so 10.0.0.9 lands before 10.0.0.10. */
  function ipKey(ip) {
    if (!ip) return "";
    var octets = ip.split(".");
    if (octets.length === 4 && octets.every(function (o) { return /^\d{1,3}$/.test(o); })) {
      return octets.map(function (o) { return o.padStart(3, "0"); }).join(".");
    }
    return ip.toLowerCase();
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

  /* ------------------------------------------------------------ rendering */

  function applyLayout() {
    var classes = ["sheet", "cols-" + state.cols];
    if (state.groupBy) classes.push("is-grouped");
    if ((el.filter.value || "").trim()) classes.push("is-filtering");
    el.sheet.className = classes.join(" ");
  }

  function render() {
    var ordered = sortResults(state.results);
    var fragment = document.createDocumentFragment();

    if (state.groupBy) {
      var groups = groupResults(ordered);
      state.groupCount = groups.size;
      groups.forEach(function (items, domain) {
        fragment.appendChild(buildGroup(domain, items));
      });
    } else {
      state.groupCount = 0;
      ordered.forEach(function (result) { fragment.appendChild(buildFrame(result)); });
    }

    el.sheet.textContent = "";
    el.sheet.appendChild(fragment);

    el.empty.hidden = state.results.length > 0;
    el.bulk.hidden = !(state.groupBy && state.results.length);

    applyLayout();
    updateStatus();
    applyFilter();
  }

  function applyFilter() {
    var term = (el.filter.value || "").trim().toLowerCase();
    var shown = 0;

    Array.prototype.forEach.call(el.sheet.querySelectorAll(".frame"), function (frame) {
      var match = !term || frame.dataset.haystack.indexOf(term) !== -1;
      frame.classList.toggle("is-hidden", !match);
      if (match) shown += 1;
    });

    // A group with nothing left in it just becomes noise.
    var groupsShown = 0;
    Array.prototype.forEach.call(el.sheet.querySelectorAll(".group"), function (group) {
      var visible = group.querySelectorAll(".frame:not(.is-hidden)").length;
      group.hidden = visible === 0;
      if (visible) groupsShown += 1;
    });

    applyLayout();

    if (!term) {
      updateStatus();
      return;
    }

    el.status.textContent = "";
    el.status.append(
      document.createTextNode("Showing "),
      strong(fmt(shown)),
      document.createTextNode(" of " + fmt(state.results.length) + " loaded frames")
    );
    if (state.groupBy) {
      el.status.append(document.createTextNode(" across " + plural(groupsShown, "domain", "domains")));
    }
    el.status.append(document.createTextNode("."));
  }

  function updateStatus() {
    if (!state.results.length) {
      el.status.textContent = "Nothing on the sheet yet.";
      el.more.hidden = true;
      return;
    }

    el.status.textContent = "";
    el.status.append(strong(fmt(state.results.length)), document.createTextNode(" frames"));

    if (state.groupBy) {
      el.status.append(document.createTextNode(" in " + plural(state.groupCount, "domain", "domains")));
    }

    if (typeof state.total === "number") {
      el.status.append(document.createTextNode(
        state.totalExact
          ? " of " + fmt(state.total) + " matches"
          : " of more than " + fmt(state.total) + " matches"
      ));
    }
    el.status.append(document.createTextNode("."));

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

    var params = { q: query, size: el.size.value };
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
          state.collapsed = {};
          window.scrollTo({ top: 0, behavior: "smooth" });
        }

        state.query = body.meta.query;
        state.size = body.meta.size;
        state.total = body.meta.total;
        state.totalExact = body.meta.total_is_exact;
        state.hasMore = body.meta.has_more;
        state.cursor = body.meta.next_cursor;

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
        el.status.textContent = windows.map(function (w) {
          var q = search[w];
          var left = (q.limit || 0) - (q.used || 0);
          return left + " of " + q.limit + " searches left this " + w;
        }).join(", ") + ".";
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

  el.group.addEventListener("change", function () {
    state.groupBy = el.group.checked;
    render();
  });

  el.collapseAll.addEventListener("click", function () { setAllCollapsed(true); });
  el.expandAll.addEventListener("click", function () { setAllCollapsed(false); });

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

  Array.prototype.forEach.call(document.querySelectorAll(".segment__btn"), function (button) {
    button.addEventListener("click", function () {
      state.cols = parseInt(button.dataset.cols, 10);
      applyLayout();
      document.querySelectorAll(".segment__btn").forEach(function (b) {
        b.classList.toggle("is-on", b === button);
        b.setAttribute("aria-pressed", String(b === button));
      });
    });
  });

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
})();
