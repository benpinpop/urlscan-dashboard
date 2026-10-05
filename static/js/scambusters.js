/* Scambusters reporter: report a scam site (plus wallets) and look up whether
 * a site is already known.
 *
 * Requests go to this app's own /api/scambusters/* routes, which forward them
 * to Scambusters with the user's key (so the page stays same-origin and the
 * Content-Security-Policy stays strict). Wallet rules are NOT implemented here:
 * every address is checked by /api/wallets/check, backed by the wallet module
 * ported from the ScamHunt CTF, and re-checked server-side on submit. The row
 * behaviour (instant format guess, debounced server check, "user chose a
 * chain" handling) is ported from the CTF's submit.js.
 *
 * The key lives in sessionStorage under "scambusters_api_key", is shown masked
 * (sb_••••••••1234) and never appears in logs or messages beyond its last 4.
 *
 * Public surface, used by app.js and the analyzer:
 *   ScambustersReporter.open({ siteUrl, focusKey })
 *   ScambustersReporter.close()
 *   ScambustersReporter.isOpen()
 *   ScambustersReporter.hasKey()
 *   ScambustersReporter.describeCheck(siteUrl) -> Promise<{tone, title, detail, action}>
 */

window.ScambustersReporter = (function () {
  "use strict";

  var STORAGE_KEY = "scambusters_api_key";
  var BLOCKED_KEY = "scambusters_submit_blocked";   /* "not on the approval list" for the saved key */
  var KEY_SHAPE = /^sb_[A-Za-z0-9_\-]{8,128}$/;
  var EVM = ["eth", "bsc", "matic", "arb", "avax", "op"];
  var B58 = /^[1-9A-HJ-NP-Za-km-z]+$/;
  var REQUEST_TIMEOUT_MS = 30000;   /* the server gives Scambusters 20 s */
  var DEFAULT_COOLDOWN_S = 30;

  var el = {};
  var state = {
    ready: false,
    memoryKey: "",          /* used only if sessionStorage is blocked */
    storageBlocked: false,
    editingKey: false,
    submitting: false,
    cooldownUntil: 0,
    cooldownTimer: null,
    maxWallets: 30,
    lastFocus: null,
    rowSeq: 0
  };

  /* ------------------------------------------------------------ utilities */

  function node(tag, className, text) {
    var n = document.createElement(tag);
    if (className) n.className = className;
    if (text !== undefined && text !== null) n.textContent = text;
    return n;
  }

  function clear(target) { while (target.firstChild) target.removeChild(target.firstChild); }

  function debounce(fn, ms) {
    var timer;
    return function () {
      var args = arguments;
      clearTimeout(timer);
      timer = setTimeout(function () { fn.apply(null, args); }, ms);
    };
  }

  function formatLocal(iso) {
    if (!iso) return "";
    var date = new Date(iso);
    if (isNaN(date.getTime())) return String(iso);
    try {
      return new Intl.DateTimeFormat(undefined, {
        year: "numeric", month: "short", day: "numeric",
        hour: "numeric", minute: "2-digit", second: "2-digit", timeZoneName: "short"
      }).format(date);
    } catch (e) {
      return date.toLocaleString();
    }
  }

  /* Defanged URLs are common in threat intel: hxxps://evil[.]example */
  function refang(value) {
    return String(value || "").trim()
      .replace(/^hxxp(s?):\/\//i, "http$1://")
      .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]/gi, ".")
      .replace(/\[:\]/g, ":");
  }

  /* Mirrors the server's site_hostname(): a parseable hostname, https:// assumed. */
  function siteHostname(value) {
    var text = refang(value);
    if (!text || text.length > 2048 || /[\s\x00-\x1f\x7f]/.test(text)) return "";
    var url;
    try {
      url = new URL(/^[a-z][a-z0-9+.\-]*:\/\//i.test(text) ? text : "https://" + text);
    } catch (e) {
      return "";
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") return "";
    var host = url.hostname.replace(/\.$/, "");
    var labels = host.split(".");
    if (labels.length < 2 || host.length > 253) return "";
    for (var i = 0; i < labels.length; i++) {
      if (!labels[i] || labels[i].length > 63) return "";
    }
    if (/[\[\]:%]/.test(host)) return "";
    return host;
  }

  /* Quick format guess so the dropdown pre-selects instantly (ported from the
     CTF's submit.js). Checksums always come from the server. */
  function guessChain(address) {
    var a = address.trim();
    if (!a) return "";
    if (/^0x[0-9a-fA-F]{40}$/.test(a)) return "eth";
    var low = a.toLowerCase();
    if (low.indexOf("x-avax1") === 0) return "avax";
    if (low.indexOf("bc1") === 0) return "btc";
    if (low.indexOf("ltc1") === 0) return "ltc";
    if (low.indexOf("addr1") === 0) return "ada";
    if (low.indexOf("bitcoincash:") === 0 || /^[qp][qpzry9x8gf2tvdw0s3jn54khce6mua7l]{41}$/.test(low)) return "bch";
    if (/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(a)) return "xrp";   /* XRP ADDITION */
    if (B58.test(a)) {
      var first = a.charAt(0);
      if (first === "T" && a.length === 34) return "trx";
      if (first === "1" || first === "3") return "btc";
      if (first === "L" || first === "M") return "ltc";
      if (first === "D") return "doge";
      if (first === "X") return "dash";
    }
    return "";
  }

  /* ----------------------------------------------------------------- key */

  function readKey() {
    if (state.storageBlocked) return state.memoryKey;
    try {
      return window.sessionStorage.getItem(STORAGE_KEY) || "";
    } catch (e) {
      state.storageBlocked = true;
      return state.memoryKey;
    }
  }

  function writeKey(value) {
    state.memoryKey = value || "";
    state.blockedInMemory = false;
    try {
      if (value) window.sessionStorage.setItem(STORAGE_KEY, value);
      else window.sessionStorage.removeItem(STORAGE_KEY);
      window.sessionStorage.removeItem(BLOCKED_KEY);   /* a new key gets a fresh chance */
    } catch (e) {
      state.storageBlocked = true;
    }
  }

  function maskKey(key) {
    return key ? "sb_••••••••" + key.slice(-4) : "";
  }

  /* Never show the key in a message: replace it with its masked form. */
  function redact(text) {
    var key = readKey();
    text = String(text || "");
    return key ? text.split(key).join(maskKey(key)) : text;
  }

  function submitBlocked() {
    try { return window.sessionStorage.getItem(BLOCKED_KEY) === "1"; } catch (e) { return state.blockedInMemory === true; }
  }

  function setSubmitBlocked(blocked) {
    state.blockedInMemory = blocked;
    try {
      if (blocked) window.sessionStorage.setItem(BLOCKED_KEY, "1");
      else window.sessionStorage.removeItem(BLOCKED_KEY);
    } catch (e) { /* memory flag above still applies */ }
  }

  function paintKey() {
    var key = readKey();
    var editing = state.editingKey || !key;
    el.keyEdit.hidden = !editing;
    el.keySaved.hidden = editing;
    el.keyCancel.hidden = !key;
    el.keyMask.textContent = maskKey(key);
    el.keySection.classList.toggle("is-set", !!key);
    updateSubmitState();
  }

  function editKey(focus) {
    state.editingKey = true;
    el.keyInput.value = "";
    el.keyError.hidden = true;
    paintKey();
    if (focus) el.keyInput.focus();
  }

  function saveKey() {
    var value = (el.keyInput.value || "").trim();
    if (!KEY_SHAPE.test(value)) {
      el.keyError.textContent = "That doesn't look like a Scambusters key — it starts with sb_ (get one with /get-api-key in Discord).";
      el.keyError.hidden = false;
      el.keyInput.focus();
      return;
    }
    writeKey(value);
    el.keyInput.value = "";
    el.keyError.hidden = true;
    state.editingKey = false;
    if (state.storageBlocked) {
      el.keyError.textContent = "This browser blocked session storage, so the key is kept only until you reload the page.";
      el.keyError.hidden = false;
    }
    paintKey();
    el.site.focus();
  }

  /* --------------------------------------------------------------- rows */

  function rows() {
    return Array.prototype.slice.call(el.rows.querySelectorAll(".sb-wallet"));
  }

  function rowParts(row) {
    return {
      address: row.querySelector(".sb-wallet__address"),
      chain: row.querySelector(".sb-wallet__chain"),
      tagBox: row.querySelector(".sb-wallet__tag"),
      tag: row.querySelector(".sb-wallet__tag-input"),
      tagError: row.querySelector(".sb-wallet__tag-error"),
      status: row.querySelector(".sb-wallet__status")
    };
  }

  function setRowStatus(row, stateName, text) {
    var status = rowParts(row).status;
    row.setAttribute("data-state", stateName);
    row.classList.toggle("has-error", stateName === "invalid");
    status.className = "sb-wallet__status" + (stateName === "valid" ? " is-valid"
      : stateName === "invalid" ? " is-invalid" : stateName === "pending" ? " is-pending" : "");
    status.textContent = text || "";
    updateSubmitState();
  }

  /* XRP: the destination tag is a required sub-input, shown only for XRP. */
  function tagProblem(row) {
    var parts = rowParts(row);
    if (parts.chain.value !== "xrp" || row.getAttribute("data-state") === "empty") return "";
    var tag = parts.tag.value.trim();
    if (!tag) return "Enter the destination tag (memo) shown with this XRP address.";
    if (!/^[0-9]+$/.test(tag)) return "A destination tag is a whole number (digits only).";
    if (Number(tag) > 4294967295) return "A destination tag is at most 4294967295.";
    return "";
  }

  function paintTag(row, showError) {
    var parts = rowParts(row);
    var isXrp = parts.chain.value === "xrp";
    parts.tagBox.hidden = !isXrp;
    parts.tag.disabled = !isXrp;          /* never submittable for other chains */
    if (!isXrp) {
      parts.tag.value = "";
      parts.tagError.hidden = true;
      parts.tag.removeAttribute("aria-invalid");
      return;
    }
    var problem = tagProblem(row);
    var visible = problem && (showError || parts.tag.getAttribute("data-touched") === "1");
    parts.tagError.textContent = visible ? problem : "";
    parts.tagError.hidden = !visible;
    if (visible) parts.tag.setAttribute("aria-invalid", "true"); else parts.tag.removeAttribute("aria-invalid");
  }

  function checkRow(row) {
    var parts = rowParts(row);
    var address = parts.address.value.trim();
    var token = String(Date.now()) + Math.random();
    row.setAttribute("data-token", token);
    if (!address) {
      setRowStatus(row, "empty", "");
      paintTag(row, false);
      return Promise.resolve();
    }

    /* Instant pre-selection unless the user picked a chain for this row. */
    var guess = guessChain(address);
    if (!row.hasAttribute("data-user-chose") && guess && parts.chain.value !== guess &&
        !(guess === "eth" && EVM.indexOf(parts.chain.value) !== -1)) {
      parts.chain.value = guess;
    }
    paintTag(row, false);
    setRowStatus(row, "pending", "Checking…");

    return fetch("/api/wallets/check", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ address: address, chain: parts.chain.value }),
      cache: "no-store"
    }).then(function (response) {
      if (!response.ok) throw new Error(String(response.status));
      return response.json();
    }).then(function (data) {
      if (row.getAttribute("data-token") !== token) return;   /* superseded by a newer check */
      if (!row.hasAttribute("data-user-chose") && data.chain && !parts.chain.value) parts.chain.value = data.chain;
      paintTag(row, false);
      if (data.valid) {
        var text = "✓ Valid " + data.chain_label + " address" + (data.format ? " · " + data.format : "");
        if (EVM.indexOf(data.chain) !== -1 && !row.hasAttribute("data-user-chose")) {
          text += " — 0x addresses look the same on every EVM network; change it if the site uses another.";
        } else if (data.chain === "xrp") {
          text += " — add its destination tag below.";
        }
        row.setAttribute("data-canonical", data.canonical || address);
        setRowStatus(row, "valid", text);
      } else {
        row.removeAttribute("data-canonical");
        setRowStatus(row, "invalid", "✗ " + (data.error || "Not a valid address for any supported chain."));
      }
    }).catch(function () {
      if (row.getAttribute("data-token") !== token) return;
      setRowStatus(row, "unchecked", "Couldn't check this address right now — edit it or try again.");
    });
  }

  function addRow(values) {
    if (rows().length >= state.maxWallets) {
      el.cap.hidden = false;
      return null;
    }
    var fragment = el.template.content.cloneNode(true);
    var row = fragment.querySelector(".sb-wallet");
    var parts = rowParts(row);
    var id = "sb-wallet-" + (++state.rowSeq);
    parts.address.id = id;
    parts.tag.id = id + "-tag";
    row.querySelector(".sb-wallet__tag .label").setAttribute("for", parts.tag.id);
    el.rows.appendChild(fragment);
    wireRow(row);
    if (values && values.address) {
      parts.address.value = values.address;
      if (values.chain) { parts.chain.value = values.chain; row.setAttribute("data-user-chose", ""); }
      if (values.tag) parts.tag.value = values.tag;
      checkRow(row);
    }
    updateCap();
    return row;
  }

  function resetRow(row) {
    var parts = rowParts(row);
    parts.address.value = "";
    parts.chain.value = "";
    parts.tag.value = "";
    parts.tag.removeAttribute("data-touched");
    row.removeAttribute("data-user-chose");
    row.removeAttribute("data-canonical");
    setRowStatus(row, "empty", "");
    paintTag(row, false);
  }

  function wireRow(row) {
    var parts = rowParts(row);
    var debounced = debounce(function () { checkRow(row); }, 300);
    parts.address.addEventListener("input", function () {
      if (!parts.address.value.trim()) row.removeAttribute("data-user-chose");
      parts.tag.removeAttribute("data-touched");   /* a new address gets a fresh, un-nagged tag field */
      setRowStatus(row, parts.address.value.trim() ? "pending" : "empty", "");   /* no stale ✓ while typing */
      debounced();
    });
    parts.address.addEventListener("paste", function () { setTimeout(function () { checkRow(row); }, 0); });
    parts.chain.addEventListener("change", function () {
      if (parts.chain.value) row.setAttribute("data-user-chose", ""); else row.removeAttribute("data-user-chose");
      checkRow(row);
    });
    parts.tag.addEventListener("input", function () { paintTag(row, false); updateSubmitState(); });
    parts.tag.addEventListener("blur", function () {
      parts.tag.setAttribute("data-touched", "1");
      paintTag(row, false);
    });
    row.querySelector(".sb-wallet__remove").addEventListener("click", function () {
      if (rows().length > 1) {
        row.remove();
        updateCap();
        updateSubmitState();
      } else {
        resetRow(row);
      }
    });
  }

  function updateCap() {
    var full = rows().length >= state.maxWallets;
    el.addWallet.disabled = full;
    el.cap.hidden = !full;   /* the limit is explained the moment it is reached, never silent */
  }

  /* ------------------------------------------------------- submit gating */

  function submitReason() {
    if (state.submitting) return "Sending…";
    if (!readKey() || state.editingKey) return "Save your Scambusters API key first.";
    if (submitBlocked()) return "This key isn't on the submit approval list yet (see above). Checking sites still works.";
    var remaining = Math.ceil((state.cooldownUntil - Date.now()) / 1000);
    if (remaining > 0) return "Rate limit reached — you can submit again in " + remaining + "s.";
    if (!el.site.value.trim()) return "Enter the scam site's URL.";
    if (!siteHostname(el.site.value)) return "The site URL needs a hostname, like scam-site.example.";
    var list = rows();
    var filled = list.filter(function (r) { return r.getAttribute("data-state") !== "empty"; });
    if (filled.length > state.maxWallets) return "A report can hold at most " + state.maxWallets + " wallets.";
    if (filled.some(function (r) { return r.getAttribute("data-state") === "pending"; })) return "Checking wallets…";
    if (filled.some(function (r) { return r.getAttribute("data-state") === "unchecked"; })) {
      return "Some wallets couldn't be checked — edit or re-select their chain to try again.";
    }
    if (filled.some(function (r) { return r.getAttribute("data-state") !== "valid"; })) {
      return "Fix or remove the wallets marked ✗ — every address must pass its format check.";
    }
    if (filled.some(function (r) { return tagProblem(r); })) return "Add the destination tag for each XRP wallet.";
    return "";
  }

  function updateSubmitState() {
    if (!state.ready) return;
    var reason = submitReason();
    el.submit.disabled = !!reason;
    el.submitHint.textContent = reason;
    var remaining = Math.ceil((state.cooldownUntil - Date.now()) / 1000);
    el.submit.textContent = state.submitting ? "Submitting…"
      : remaining > 0 ? "Try again in " + remaining + "s" : "Submit to Scambusters";
    el.submit.classList.toggle("is-busy", state.submitting);
    el.submit.setAttribute("aria-busy", state.submitting ? "true" : "false");
  }

  function startCooldown(seconds) {
    state.cooldownUntil = Date.now() + seconds * 1000;
    clearInterval(state.cooldownTimer);
    state.cooldownTimer = setInterval(function () {
      if (Date.now() >= state.cooldownUntil) {
        clearInterval(state.cooldownTimer);
        state.cooldownUntil = 0;
      }
      updateSubmitState();
    }, 1000);
    updateSubmitState();
  }

  /* ---------------------------------------------------------- results */

  function showResult(tone, title, lines, actions) {
    clear(el.resultBody);
    el.result.className = "sb-result sb-result--" + tone;
    el.result.setAttribute("role", tone === "bad" ? "alert" : "status");
    el.resultBody.appendChild(node("p", "sb-result__title", title));
    (lines || []).forEach(function (line) {
      if (!line) return;
      if (line.nodeType) { el.resultBody.appendChild(line); return; }
      el.resultBody.appendChild(node("p", "sb-result__line", redact(line)));
    });
    if (actions && actions.length) {
      var bar = node("div", "panel__actions");
      actions.forEach(function (action) {
        var button = node("button", "btn btn--small " + (action.primary ? "btn--primary" : "btn--ghost"), action.label);
        button.type = "button";
        button.addEventListener("click", action.run);
        bar.appendChild(button);
      });
      el.resultBody.appendChild(bar);
    }
    el.result.hidden = false;
    el.result.scrollIntoView({ block: "nearest" });
  }

  function hideResult() { el.result.hidden = true; clear(el.resultBody); }

  function fact(label, value) {
    var line = node("p", "sb-result__line");
    line.appendChild(node("span", "sb-result__label", label + " "));
    line.appendChild(node("span", "mono", value));
    return line;
  }

  function clearFieldErrors() {
    el.siteError.hidden = true;
    el.site.removeAttribute("aria-invalid");
    rows().forEach(function (row) { paintTag(row, false); });
  }

  /* Maps "site_url …" and "wallets[N].field …" onto the matching inputs;
     anything else is listed in the result banner. */
  function applyValidationErrors(errors, sentRows) {
    var unmapped = [];
    (errors || []).forEach(function (raw) {
      var message = redact(String(raw));
      var wallet = /^wallets\[(\d+)\]\.?(\w*)\s*(.*)$/.exec(message);
      if (/^site_url\b/.test(message)) {
        el.siteError.textContent = message.replace(/^site_url\s*/, "Site URL: ");
        el.siteError.hidden = false;
        el.site.setAttribute("aria-invalid", "true");
      } else if (wallet && sentRows[Number(wallet[1])]) {
        var row = sentRows[Number(wallet[1])];
        var text = wallet[3] || message;
        if (wallet[2] === "xrp_dest_tag") {
          var parts = rowParts(row);
          parts.tagError.textContent = text;
          parts.tagError.hidden = false;
          parts.tag.setAttribute("aria-invalid", "true");
        } else {
          setRowStatus(row, "invalid", "✗ " + (wallet[2] ? wallet[2] + ": " : "") + text);
        }
      } else {
        unmapped.push(message);
      }
    });
    return unmapped;
  }

  function resetForm() {
    el.site.value = "";
    rows().forEach(function (row, i) { if (i === 0) resetRow(row); else row.remove(); });
    updateCap();
    clearFieldErrors();
    updateSubmitState();
  }

  function errorText(body, fallback) {
    if (body && typeof body.error === "string") return body.error;
    if (body && body.error && typeof body.error.message === "string") return body.error.message;
    return fallback;
  }

  function handleSubmitResponse(status, body, retryAfter, sentRows) {
    body = body || {};
    var ok = status >= 200 && status < 300;
    if (ok && body.status !== "duplicate" && (status === 201 || body.status === "queued")) {
      resetForm();
      showResult("ok", "Report queued — thank you.", [
        body.submission_id ? fact("Submission ID", body.submission_id) : null,
        body.queued_ts_utc ? fact("Queued", formatLocal(body.queued_ts_utc)) : null,
        fact("Wallets", String(body.wallet_count != null ? body.wallet_count : 0)),
        body.site_url ? fact("Site", body.site_url) : null
      ], [{ label: "Report another site", primary: true, run: function () { hideResult(); el.site.focus(); } }]);
      return;
    }
    if (ok) {   /* 200 = duplicate */
      showResult("info", "Already submitted — Scambusters has this exact report.", [
        body.submission_key ? fact("Matches submission", body.submission_key) : null,
        "Found new wallets for this site? Add them and submit again."
      ]);
      return;
    }
    if (status === 400) {
      var unmapped = applyValidationErrors(body.errors || (body.error ? [errorText(body)] : []), sentRows);
      showResult("bad", "Scambusters couldn't accept this report — fix the highlighted fields.",
        unmapped.length ? unmapped : []);
      updateSubmitState();
      return;
    }
    if (status === 401) {
      showResult("bad", "Your API key is invalid or revoked.", [
        body.source === "local" ? errorText(body, "") : "Check you copied the whole key; after rotating, the old key stops working."
      ]);
      editKey(true);
      return;
    }
    if (status === 403 && /expired/i.test(errorText(body, ""))) {
      showResult("bad", "Your API key has expired — use /rotate-api-key in Discord to get a new one.",
        ["Then paste the new key above."]);
      editKey(true);
      return;
    }
    if (status === 403) {
      setSubmitBlocked(true);
      showResult("bad", "Your key can't submit yet.", [
        "Share your scraper/auto-submit source code with Sam for review to get added to the approval list.",
        "Checking whether a site is known (/api/check) remains available with this key."
      ]);
      updateSubmitState();
      return;
    }
    if (status === 429) {
      var seconds = parseInt(retryAfter, 10);
      startCooldown(seconds > 0 && seconds <= 600 ? seconds : DEFAULT_COOLDOWN_S);
      showResult("warn", "Rate limit exceeded — try again shortly.", [errorText(body, "")]);
      return;
    }
    if (status === 503) {
      showResult("warn", "Scambusters is temporarily unavailable — please retry.", [errorText(body, "")],
        [{ label: "Retry now", primary: true, run: function () { hideResult(); submitReport(); } }]);
      return;
    }
    showResult("bad", "Something went wrong — please retry or contact support.",
      [errorText(body, "HTTP " + status)]);
  }

  function buildPayload() {
    var siteUrl = refang(el.site.value);
    var wallets = [];
    var sentRows = [];
    rows().forEach(function (row) {
      if (row.getAttribute("data-state") === "empty") return;
      var parts = rowParts(row);
      var wallet = { address: row.getAttribute("data-canonical") || parts.address.value.trim(), chain: parts.chain.value };
      if (wallet.chain === "xrp") wallet.xrp_dest_tag = parts.tag.value.trim();   /* only ever on XRP */
      wallets.push(wallet);
      sentRows.push(row);
    });
    var payload = { site_url: siteUrl };
    if (wallets.length) payload.wallets = wallets;   /* omitted for site-only reports */
    return { payload: payload, sentRows: sentRows };
  }

  function submitReport() {
    var reason = submitReason();
    if (reason) { updateSubmitState(); return; }
    var built = buildPayload();
    if ((built.payload.wallets || []).length > state.maxWallets) { el.cap.hidden = false; return; }

    clearFieldErrors();
    hideResult();
    state.submitting = true;
    updateSubmitState();

    var controller = window.AbortController ? new AbortController() : null;
    var timer = setTimeout(function () { if (controller) controller.abort(); }, REQUEST_TIMEOUT_MS);

    fetch("/api/scambusters/submit", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json", "X-Scambusters-Key": readKey() },
      body: JSON.stringify(built.payload),
      cache: "no-store",
      signal: controller ? controller.signal : undefined
    }).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (body) {
        handleSubmitResponse(response.status, body, response.headers.get("Retry-After"), built.sentRows);
      });
    }).catch(function (error) {
      var timedOut = error && error.name === "AbortError";
      showResult("bad", "Something went wrong — please retry or contact support.", [
        timedOut ? "Scambusters didn't answer in time." : "The request didn't reach this server."
      ]);
    }).finally(function () {
      clearTimeout(timer);
      state.submitting = false;
      updateSubmitState();
    });
  }

  /* ------------------------------------------------------------- lookup */

  /* Used by the analyzer's "Check Scambusters" button. Resolves (never rejects)
     with a small display model so the analyzer needs no Scambusters knowledge. */
  function describeCheck(siteUrl) {
    var keyAction = { label: "Add Scambusters key", run: function () { open({ siteUrl: siteUrl, focusKey: true }); } };
    var reportAction = { label: "Report to Scambusters", run: function () { open({ siteUrl: siteUrl }); } };
    if (!readKey()) {
      return Promise.resolve({ tone: "info", title: "Add your Scambusters API key to check this site.", detail: "", action: keyAction });
    }
    if (!siteHostname(siteUrl)) {
      return Promise.resolve({ tone: "bad", title: "This scan has no site URL to look up.", detail: "", action: null });
    }
    var controller = window.AbortController ? new AbortController() : null;
    var timer = setTimeout(function () { if (controller) controller.abort(); }, REQUEST_TIMEOUT_MS);
    return fetch("/api/scambusters/check?site_url=" + encodeURIComponent(refang(siteUrl)), {
      headers: { Accept: "application/json", "X-Scambusters-Key": readKey() },
      cache: "no-store",
      signal: controller ? controller.signal : undefined
    }).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (body) {
        return describeCheckResponse(response.status, body, reportAction, keyAction);
      });
    }).catch(function () {
      return { tone: "bad", title: "Couldn't reach Scambusters — please retry.", detail: "", action: null };
    }).finally(function () { clearTimeout(timer); });
  }

  function describeCheckResponse(status, body, reportAction, keyAction) {
    body = body || {};
    if (status === 200) {
      var matched = body.site_key ? "Matched as " + body.site_key + "." : "";
      var siteStatus = body.site_status && body.site_status !== "unknown" ? " Status: " + body.site_status + "." : "";
      if (body.has_wallets && body.stale) {
        return { tone: "warn", title: "Reported, but its wallets are over 30 days old.",
          label: "Stale Wallets", detail: "Latest wallet collected " + formatLocal(body.latest_wallet_collected_utc) + "." + siteStatus
            + " Scammers rotate wallets — fresh ones earn points. " + matched, action: reportAction };
      }
      if (body.has_wallets) {
        return { tone: "bad", title: "Already reported — Scambusters has wallets for this site.",
          label: "Reported", detail: "Latest wallet collected " + formatLocal(body.latest_wallet_collected_utc) + "." + siteStatus + " " + matched,
          action: reportAction };
      }
      if (body.is_reported === true || (body.site_status && body.site_status !== "unknown")) {
        return { tone: "warn", title: "Reported, but no wallets collected yet.", label: "No Wallets",
          detail: "Site status: " + (body.site_status || "known") + ". Found its wallets? Report them. " + matched,
          action: reportAction };
      }
      if (body.is_reported === false || body.site_status === "unknown") {
        return { tone: "ok", title: "Not reported to Scambusters yet.", label: "Unreported", detail: matched, action: reportAction };
      }
      return { tone: "info", title: "Scambusters has no wallets recorded for this site.", detail: matched, action: reportAction };
    }
    var message = redact(errorText(body, "HTTP " + status));
    if (status === 401) return { tone: "bad", title: "Your Scambusters API key is invalid or revoked.", detail: message, action: keyAction };
    if (status === 403) {
      return { tone: "bad", title: "Your API key has expired — use /rotate-api-key in Discord to get a new one.",
        detail: "", action: keyAction };
    }
    if (status === 429) return { tone: "warn", title: "Check rate limit reached — try again shortly.", detail: message, action: null };
    if (status === 400) return { tone: "bad", title: "Scambusters couldn't read that site URL.", detail: message, action: null };
    return { tone: "bad", title: "Couldn't check Scambusters right now — please retry.", detail: message, action: null };
  }

  /* -------------------------------------------------------- open / close */

  function onKeydown(event) {
    if (event.key !== "Escape" || el.panel.hidden) return;
    event.stopPropagation();   /* capture phase: keep the analyzer underneath open */
    close();
  }

  function open(options) {
    options = options || {};
    build();
    state.lastFocus = document.activeElement;
    if (options.siteUrl) {
      var incoming = String(options.siteUrl);
      if (el.site.value.trim() !== incoming) {
        el.site.value = incoming;
        clearFieldErrors();
        hideResult();
      }
    }
    el.panel.hidden = false;
    paintKey();
    if (options.focusKey || !readKey()) editKey(true);
    else if (!el.site.value.trim()) el.site.focus();
    else {
      var first = rowParts(rows()[0]).address;
      first.focus();
    }
    updateSubmitState();
  }

  function close() {
    if (!state.ready || el.panel.hidden) return;
    el.panel.hidden = true;
    if (state.lastFocus && state.lastFocus.focus) state.lastFocus.focus();
  }

  function build() {
    if (state.ready) return;
    el.panel = document.getElementById("sb-panel");
    if (!el.panel) return;
    el.close = document.getElementById("sb-close");
    el.keySection = document.getElementById("sb-key");
    el.keyEdit = document.getElementById("sb-key-edit");
    el.keyInput = document.getElementById("sb-key-input");
    el.keySave = document.getElementById("sb-key-save");
    el.keyCancel = document.getElementById("sb-key-cancel");
    el.keyError = document.getElementById("sb-key-error");
    el.keySaved = document.getElementById("sb-key-saved");
    el.keyMask = document.getElementById("sb-key-mask");
    el.keyEditBtn = document.getElementById("sb-key-edit-btn");
    el.keyClear = document.getElementById("sb-key-clear");
    el.result = document.getElementById("sb-result");
    el.resultBody = document.getElementById("sb-result-body");
    el.resultClose = document.getElementById("sb-result-close");
    el.form = document.getElementById("sb-form");
    el.site = document.getElementById("sb-site");
    el.siteError = document.getElementById("sb-site-error");
    el.rows = document.getElementById("sb-wallet-rows");
    el.addWallet = document.getElementById("sb-add-wallet");
    el.cap = document.getElementById("sb-cap");
    el.submit = document.getElementById("sb-submit");
    el.submitHint = document.getElementById("sb-submit-hint");
    el.template = document.getElementById("sb-wallet-template");
    state.maxWallets = parseInt(el.form.getAttribute("data-max-wallets"), 10) || 30;

    el.close.addEventListener("click", close);
    el.panel.addEventListener("click", function (event) { if (event.target === el.panel) close(); });
    document.addEventListener("keydown", onKeydown, true);

    el.keySave.addEventListener("click", saveKey);
    el.keyInput.addEventListener("keydown", function (event) {
      if (event.key === "Enter") { event.preventDefault(); saveKey(); }
    });
    el.keyCancel.addEventListener("click", function () { state.editingKey = false; el.keyError.hidden = true; paintKey(); });
    el.keyEditBtn.addEventListener("click", function () { editKey(true); });
    el.keyClear.addEventListener("click", function () { writeKey(""); editKey(true); });
    el.resultClose.addEventListener("click", hideResult);

    el.site.addEventListener("input", function () {
      el.siteError.hidden = true;
      el.site.removeAttribute("aria-invalid");
      updateSubmitState();
    });
    el.site.addEventListener("blur", function () {
      var fixed = refang(el.site.value);
      if (fixed !== el.site.value.trim()) el.site.value = fixed;
      if (el.site.value.trim() && !siteHostname(el.site.value)) {
        el.siteError.textContent = "Site URL: this has no hostname Scambusters can read (e.g. scam-site.example).";
        el.siteError.hidden = false;
        el.site.setAttribute("aria-invalid", "true");
      }
      updateSubmitState();
    });

    el.addWallet.addEventListener("click", function () {
      var row = addRow();
      if (row) rowParts(row).address.focus();
      else el.cap.hidden = false;
    });

    el.form.addEventListener("submit", function (event) {
      event.preventDefault();
      rows().forEach(function (row) {
        rowParts(row).tag.setAttribute("data-touched", "1");
        paintTag(row, true);
      });
      submitReport();
    });

    addRow();
    state.ready = true;
    paintKey();
  }

  function init() {
    build();
    var opener = document.getElementById("sb-open");
    if (opener) opener.addEventListener("click", function () { open(); });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();

  return {
    open: open,
    close: close,
    isOpen: function () { return state.ready && !el.panel.hidden; },
    hasKey: function () { return !!readKey(); },
    describeCheck: describeCheck,
    /* exposed for tests only */
    _siteHostname: siteHostname,
    _refang: refang,
    _mask: maskKey
  };
})();
