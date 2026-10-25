/* TitanEye dataset import.
 *
 * Reads a CSV, TSV, TXT, JSON or JSONL file in the browser (nothing is
 * uploaded as a file), lets the analyst map columns to entity types, sends the
 * unique sites and wallets to /api/graph/ingest for the server's normalisation
 * rules, and hands the resulting nodes and edges to TitanEye.addFragment.
 *
 * Every cell is hostile text. It is only ever shown with textContent.
 */
window.TitanEyeImport = (function () {
  "use strict";

  var MAX_BYTES = 25 * 1024 * 1024;
  var MAX_ROWS = 200000;
  var BATCH = 150;
  var MAX_CELL = 2048;
  var MAX_ISSUES = 25;
  var WARN_NODES = 50000;
  var PRESET_PREFIX = "titaneye.mapper:";

  var ROLES = [
    { id: "ignore",         label: "Ignore this column" },
    { id: "site_url",       label: "Site URL or hostname" },
    { id: "apex_domain",    label: "Apex domain (overrides the guess)" },
    { id: "ip",             label: "IP address" },
    { id: "asn",            label: "ASN" },
    { id: "wallet_address", label: "Wallet address" },
    { id: "wallet_chain",   label: "Wallet chain (label or code)" },
    { id: "hash",           label: "SHA-256 hash" },
    { id: "tag",            label: "Tag" },
    { id: "telegram",       label: "Telegram handle" }
  ];

  /* Header names (lowercase, letters and digits only) that pick a role. */
  var ALIASES = {
    site_url: ["siteurl", "siteurloriginal", "url", "urls", "link", "website", "site", "pageurl",
               "scannedurl", "domain", "host", "hostname", "fqdn", "sitedomain"],
    apex_domain: ["sitekey", "apex", "apexdomain", "registrabledomain", "basedomain"],
    ip: ["ip", "ipaddress", "pageip", "serverip", "hostip"],
    asn: ["asn", "asnumber", "pageasn"],
    wallet_address: ["walletaddress", "wallet", "address", "addr", "cryptoaddress", "depositaddress"],
    wallet_chain: ["walletchain", "chain", "network", "blockchain", "coin", "currency"],
    hash: ["sha256", "hash", "filehash", "domhash", "texthash"],
    tag: ["tag", "tags", "campaign", "label", "category"],
    telegram: ["telegram", "tg", "telegramhandle"]
  };

  var RE_SHA256 = /^[0-9a-fA-F]{64}$/;
  var RE_IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  var RE_IPV6 = /^[0-9a-fA-F:]{2,45}$/;
  var RE_ASN = /^(?:AS)?(\d{1,10})$/i;
  var RE_HANDLE = /^[A-Za-z0-9_]{3,64}$/;
  var RE_EVM = /^0x[0-9a-fA-F]{40}$/;
  var RE_UNSAFE_TAG = /[\u0000-\u001f\u007f"\\]/;

  var el = {};
  var opts = {};
  var state = null;

  function make(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function clip(text, max) {
    text = String(text);
    return text.length > max ? text.slice(0, max - 1) + "\u2026" : text;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  /* -------------------------------------------------------------- parsing */

  /* RFC 4180 style: quoted fields, doubled quotes, newlines inside quotes. */
  function parseDelimited(text, delimiter, maxRows) {
    var rows = [];
    var row = [];
    var field = "";
    var inQuotes = false;
    var i = 0;
    var length = text.length;
    var ch;

    while (i < length) {
      ch = text.charAt(i);
      if (inQuotes) {
        if (ch === '"') {
          if (text.charAt(i + 1) === '"') { field += '"'; i += 2; continue; }
          inQuotes = false;
          i += 1;
          continue;
        }
        field += ch;
        i += 1;
        continue;
      }
      if (ch === '"' && field === "") {
        inQuotes = true;
      } else if (ch === delimiter) {
        row.push(field);
        field = "";
      } else if (ch === "\n" || ch === "\r") {
        if (ch === "\r" && text.charAt(i + 1) === "\n") i += 1;
        row.push(field);
        field = "";
        if (row.length > 1 || row[0] !== "") rows.push(row);
        row = [];
        if (rows.length > maxRows) return rows;
      } else {
        field += ch;
      }
      i += 1;
    }
    row.push(field);
    if (row.length > 1 || row[0] !== "") rows.push(row);
    return rows;
  }

  function pickDelimiter(text) {
    /* Sample several lines: a one-column header over two-column rows (a split
     * "https" / "//host/") has no delimiter on its own first line. */
    var lines = text.split(/\r\n|\n|\r/, 10);
    var best = ",";
    var bestCount = 0;
    [",", "\t", ";", "|"].forEach(function (d) {
      var count = 0;
      lines.forEach(function (line) { count += line.split(d).length - 1; });
      if (count > bestCount) { best = d; bestCount = count; }
    });
    return bestCount ? best : null;
  }

  /* Some exports split "https://host/" at the colon, leaving "https" and
   * "//host/" in neighbouring cells. Put them back together. */
  function rejoinSplitUrls(row) {
    var out = [];
    var i;
    for (i = 0; i < row.length; i++) {
      if (/^https?$/i.test(row[i].trim()) && i + 1 < row.length && row[i + 1].trim().indexOf("//") === 0) {
        out.push(row[i].trim() + ":" + row[i + 1].trim());
        i += 1;
      } else {
        out.push(row[i]);
      }
    }
    return out;
  }

  function jsonToTable(text) {
    var records = [];
    var trimmed = text.trim();
    var parsed;
    if (trimmed.charAt(0) === "[" || trimmed.charAt(0) === "{") {
      try {
        parsed = JSON.parse(trimmed);
      } catch (err) {
        parsed = null;
      }
    }
    if (parsed && !Array.isArray(parsed) && typeof parsed === "object") {
      var key;
      for (key in parsed) {
        if (Array.isArray(parsed[key])) { parsed = parsed[key]; break; }
      }
    }
    if (Array.isArray(parsed)) {
      records = parsed;
    } else {
      trimmed.split(/\r\n|\n|\r/).forEach(function (line) {
        if (!line.trim()) return;
        try { records.push(JSON.parse(line)); } catch (err) { /* skip bad line */ }
      });
    }
    var columns = [];
    var seen = {};
    records.slice(0, MAX_ROWS).forEach(function (record) {
      if (record && typeof record === "object" && !Array.isArray(record)) {
        Object.keys(record).forEach(function (k) {
          if (!seen[k]) { seen[k] = true; columns.push(k); }
        });
      }
    });
    if (!columns.length) {
      if (records.length && typeof records[0] === "string") {
        return [["value"]].concat(records.slice(0, MAX_ROWS).map(function (v) { return [String(v)]; }));
      }
      return [];
    }
    var rows = [columns];
    records.slice(0, MAX_ROWS).forEach(function (record) {
      if (!record || typeof record !== "object") return;
      rows.push(columns.map(function (k) {
        var v = record[k];
        if (v === null || v === undefined) return "";
        return typeof v === "object" ? JSON.stringify(v) : String(v);
      }));
    });
    return rows;
  }

  function parseFile(name, text) {
    if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
    var rows;
    if (/\.jsonl?$/i.test(name) || /^\s*[\[{]/.test(text.slice(0, 200))) {
      rows = jsonToTable(text);
    } else {
      var delimiter = pickDelimiter(text);
      rows = parseDelimited(text, delimiter || "\u0000", MAX_ROWS);
    }
    return rows.map(function (row) {
      return rejoinSplitUrls(row).map(function (cell) {
        cell = String(cell);
        return cell.length > MAX_CELL ? cell.slice(0, MAX_CELL) : cell;
      });
    });
  }

  /* ----------------------------------------------------------- detection */

  function normaliseHeader(text) {
    return String(text).toLowerCase().replace(/[^a-z0-9]/g, "");
  }

  function looksLike(value) {
    value = String(value || "").trim();
    if (!value) return null;
    if (RE_SHA256.test(value)) return "hash";
    if (RE_EVM.test(value)) return "wallet_address";
    if (RE_IPV4.test(value)) return "ip";
    if (/^(?:https?|hxxps?):\/\//i.test(value) || /^\/\/[^\/\s]+\./.test(value)) return "site_url";
    if (/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?:[\/:?#]\S*)?$/.test(value)) return "site_url";
    return null;
  }

  function detectRoles(header, body) {
    var roles = [];
    var used = {};
    header.forEach(function (name, col) {
      var key = normaliseHeader(name);
      var role = "ignore";
      Object.keys(ALIASES).forEach(function (candidate) {
        if (role === "ignore" && ALIASES[candidate].indexOf(key) !== -1) role = candidate;
      });
      if (role === "ignore") {
        var votes = {};
        body.slice(0, 50).forEach(function (row) {
          var guess = looksLike(row[col]);
          if (guess) votes[guess] = (votes[guess] || 0) + 1;
        });
        var best = null;
        Object.keys(votes).forEach(function (k) { if (!best || votes[k] > votes[best]) best = k; });
        if (best && votes[best] >= Math.min(3, body.length)) role = best;
      }
      if (role !== "ignore" && used[role] && role !== "tag") role = "ignore";
      if (role !== "ignore") used[role] = true;
      roles.push(role);
    });
    return roles;
  }

  function firstRowIsHeader(rows) {
    if (!rows.length) return false;
    var i;
    for (i = 0; i < rows[0].length; i++) {
      if (looksLike(rows[0][i])) return false;
    }
    return true;
  }

  /* --------------------------------------------------------- saved presets */

  function presetKey(header) {
    return PRESET_PREFIX + header.map(normaliseHeader).join("|");
  }

  function loadPreset(header) {
    try {
      var raw = window.localStorage.getItem(presetKey(header));
      var roles = raw ? JSON.parse(raw) : null;
      if (Array.isArray(roles) && roles.length === header.length) return roles;
    } catch (err) { /* storage can be blocked */ }
    return null;
  }

  function savePreset(header, roles) {
    try {
      window.localStorage.setItem(presetKey(header), JSON.stringify(roles));
    } catch (err) { /* storage can be blocked */ }
  }

  /* ------------------------------------------------------------ extraction */

  function cleanIp(value) {
    value = value.trim();
    var m = RE_IPV4.exec(value);
    if (m) {
      var ok = [m[1], m[2], m[3], m[4]].every(function (part) { return Number(part) <= 255; });
      return ok ? [m[1], m[2], m[3], m[4]].map(Number).join(".") : null;
    }
    if (value.indexOf(":") !== -1 && RE_IPV6.test(value)) return value.toLowerCase();
    return null;
  }

  function cleanHandle(value) {
    value = value.trim().replace(/^https?:\/\/(?:www\.)?(?:t|telegram)\.me\//i, "").replace(/^@/, "");
    value = value.split(/[\/?#]/)[0];
    return RE_HANDLE.test(value) ? value : null;
  }

  /* Pull the entity values out of one row according to the chosen roles. */
  function extractRow(row, roles) {
    var out = { tags: [], wallets: [], issues: [] };
    var chain = "";
    var addresses = [];
    roles.forEach(function (role, col) {
      var value = (row[col] || "").trim();
      if (!value || role === "ignore") return;
      if (role === "site_url" && !out.site) out.site = value;
      else if (role === "apex_domain" && !out.apex) out.apex = value.toLowerCase();
      else if (role === "ip") {
        var ip = cleanIp(value);
        if (ip) out.ip = ip; else out.issues.push("IP is not valid: " + clip(value, 40));
      } else if (role === "asn") {
        var m = RE_ASN.exec(value);
        if (m) out.asn = "AS" + m[1]; else out.issues.push("ASN is not valid: " + clip(value, 40));
      } else if (role === "hash") {
        if (RE_SHA256.test(value)) out.hash = value.toLowerCase();
        else out.issues.push("Hash is not a SHA-256: " + clip(value, 20));
      } else if (role === "tag") {
        if (value.length <= 100 && !RE_UNSAFE_TAG.test(value)) out.tags.push(value);
        else out.issues.push("Tag skipped (too long or has quotes/control characters)");
      } else if (role === "telegram") {
        var handle = cleanHandle(value);
        if (handle) out.telegram = handle; else out.issues.push("Telegram handle is not valid: " + clip(value, 40));
      } else if (role === "wallet_chain" && !chain) {
        chain = value;
      } else if (role === "wallet_address") {
        addresses.push(value);
      }
    });
    addresses.forEach(function (address) { out.wallets.push({ address: address, chain: chain }); });
    return out;
  }

  /* ------------------------------------------------------------- building */

  function post(body) {
    return fetch("/api/graph/ingest", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(body)
    }).then(function (response) {
      return response.json().then(function (data) {
        if (!response.ok || !data || data.ok === false) {
          throw new Error((data && data.error && data.error.message) || "Import check failed (HTTP " + response.status + ").");
        }
        return data;
      });
    });
  }

  /* Send unique sites and wallets in small batches; resolves with lookups. */
  function normaliseAll(siteList, walletList, onProgress) {
    var siteResults = new Array(siteList.length);
    var walletResults = new Array(walletList.length);
    var total = Math.max(siteList.length, walletList.length);
    var offset = 0;

    function next() {
      if (offset >= total) return Promise.resolve();
      var sites = siteList.slice(offset, offset + BATCH);
      var wallets = walletList.slice(offset, offset + BATCH);
      return post({ sites: sites, wallets: wallets }).then(function (data) {
        data.sites.forEach(function (r, i) { siteResults[offset + i] = r; });
        data.wallets.forEach(function (r, i) { walletResults[offset + i] = r; });
        offset += BATCH;
        onProgress(Math.min(offset, total), total);
        return next();
      });
    }
    return next().then(function () { return { sites: siteResults, wallets: walletResults }; });
  }

  function build(table, roles, layer, fileName, lookups) {
    var nodes = {};
    var edges = {};
    var source = "file:" + fileName;
    var report = { rows: table.length, used: 0, issues: [], issueRows: 0, counts: {} };

    function node(type, value, attrs) {
      var id = type + ":" + value;
      var existing = nodes[id];
      if (!existing) {
        existing = { id: id, type: type, label: value, attrs: {} };
        nodes[id] = existing;
        report.counts[type] = (report.counts[type] || 0) + 1;
      }
      var key;
      for (key in attrs) {
        if (!Object.prototype.hasOwnProperty.call(attrs, key)) continue;
        if (Array.isArray(attrs[key])) {
          var list = existing.attrs[key] || [];
          attrs[key].forEach(function (item) { if (list.indexOf(item) === -1) list.push(item); });
          existing.attrs[key] = list;
        } else if (existing.attrs[key] === undefined) {
          existing.attrs[key] = attrs[key];
        }
      }
      return id;
    }

    function edge(from, relation, to, row) {
      var id = from + "|" + relation + "|" + to;
      if (!edges[id]) {
        edges[id] = { id: id, source: from, target: to, type: relation,
                      attrs: { source: source, row: row, first_seen: null, last_seen: null } };
      }
    }

    table.forEach(function (item, index) {
      var x = item.extracted;
      var rowNumber = item.row;
      var linked = [];
      var problems = x.issues.slice();

      var siteId = null;
      if (x.site) {
        var site = lookups.sites[item.siteIndex];
        if (site && site.host) {
          siteId = node("site", site.host, { first_row: rowNumber });
          var apex = x.apex || site.apex;
          if (apex && /^[a-z0-9.-]{3,253}$/.test(apex)) {
            edge(siteId, "same_apex", node("apex_domain", apex, {}), rowNumber);
          }
        } else {
          problems.push("Site: " + ((site && site.error) || "not recognised") + " (" + clip(x.site, 60) + ")");
        }
      }

      var ipId = x.ip ? node("ip", x.ip, {}) : null;
      var asnId = x.asn ? node("asn", x.asn, {}) : null;
      var hashId = x.hash ? node("file_hash", x.hash, {}) : null;
      var contactId = x.telegram ? node("contact", x.telegram, {}) : null;
      var tagIds = x.tags.map(function (tag) { return node("tag", tag, {}); });

      var walletIds = [];
      x.wallets.forEach(function (w, i) {
        var result = lookups.wallets[item.walletIndexes[i]];
        if (result && result.valid) {
          walletIds.push(node("wallet", result.canonical, { chains: [result.chain] }));
        } else {
          problems.push("Wallet: " + ((result && result.error) || "not recognised") + " (" + clip(w.address, 20) + ")");
        }
      });

      if (siteId) {
        if (ipId) edge(siteId, "resolves_to", ipId, rowNumber);
        if (ipId && asnId) edge(ipId, "hosted_on", asnId, rowNumber);
        else if (asnId) edge(siteId, "hosted_on", asnId, rowNumber);
        if (hashId) edge(siteId, "serves_file", hashId, rowNumber);
        if (contactId) edge(siteId, "links_to_contact", contactId, rowNumber);
        tagIds.forEach(function (id) { edge(siteId, "tagged", id, rowNumber); });
        walletIds.forEach(function (id) { edge(siteId, "uploaded_link", id, rowNumber); });
        linked = [siteId];
      } else {
        /* No site on the row: link whatever else is there to each other. */
        var group = [ipId, asnId, hashId, contactId].concat(tagIds, walletIds).filter(Boolean);
        var a;
        var b;
        for (a = 0; a < group.length; a++) {
          for (b = a + 1; b < group.length; b++) edge(group[a], "uploaded_link", group[b], rowNumber);
        }
        linked = group;
      }

      if (linked.length) report.used += 1;
      if (problems.length) {
        report.issueRows += 1;
        if (report.issues.length < MAX_ISSUES) report.issues.push("Row " + rowNumber + ": " + problems.join("; "));
      }
    });

    var layerName = layer;
    var nodeList = Object.keys(nodes).map(function (id) {
      nodes[id].attrs.layers = [layerName];
      return nodes[id];
    });
    return { fragment: { nodes: nodeList, edges: Object.keys(edges).map(function (id) { return edges[id]; }) },
             report: report };
  }

  /* Collect unique values and remember where each row's values live. */
  function prepare(body, roles, headerRows) {
    var siteIndex = {};
    var walletIndex = {};
    var siteList = [];
    var walletList = [];
    var items = body.map(function (row, i) {
      var x = extractRow(row, roles);
      var item = { row: i + 1 + headerRows, extracted: x, siteIndex: -1, walletIndexes: [] };
      if (x.site) {
        if (siteIndex[x.site] === undefined) { siteIndex[x.site] = siteList.length; siteList.push(x.site); }
        item.siteIndex = siteIndex[x.site];
      }
      x.wallets.forEach(function (w) {
        var key = w.address + "\u0000" + w.chain;
        if (walletIndex[key] === undefined) { walletIndex[key] = walletList.length; walletList.push(w); }
        item.walletIndexes.push(walletIndex[key]);
      });
      return item;
    });
    return { items: items, siteList: siteList, walletList: walletList };
  }

  /* ------------------------------------------------------------------ UI */

  function setStatus(message, tone) {
    el.status.textContent = message;
    el.status.className = "te-import__status" + (tone ? " te-import__status--" + tone : "");
  }

  function reset() {
    state = null;
    clear(el.body);
    el.file.value = "";
    el.drop.hidden = false;
    el.check.hidden = true;
    el.add.hidden = true;
    setStatus("Choose a CSV, TSV, TXT, JSON or JSONL file. It is read in your browser.");
  }

  function renderMapper() {
    clear(el.body);
    var intro = make("p", "te-import__note",
      state.rows.length + " rows. Pick what each column holds. Wallet addresses use the chain column when there is one; " +
      "rows with a site link the site to everything else on that row.");
    el.body.appendChild(intro);

    var headerLabel = make("label", "te-import__check");
    var headerBox = make("input");
    headerBox.type = "checkbox";
    headerBox.checked = state.hasHeader;
    headerLabel.appendChild(headerBox);
    headerLabel.appendChild(make("span", null, "First row is a header"));
    headerBox.addEventListener("change", function () {
      state.hasHeader = headerBox.checked;
      configureColumns();
      renderMapper();
    });
    el.body.appendChild(headerLabel);

    var table = make("table", "te-import__table");
    var head = make("tr");
    ["Column", "Sample values", "Use as"].forEach(function (text) { head.appendChild(make("th", null, text)); });
    table.appendChild(head);

    state.header.forEach(function (name, col) {
      var tr = make("tr");
      tr.appendChild(make("td", "te-import__colname", state.hasHeader ? name : "Column " + (col + 1)));
      var samples = make("td", "te-import__samples");
      state.body.slice(0, 3).forEach(function (row) {
        samples.appendChild(make("div", null, clip(row[col] || "", 60)));
      });
      tr.appendChild(samples);
      var cell = make("td");
      var select = make("select", "field");
      select.setAttribute("aria-label", "Use column " + (col + 1) + " as");
      ROLES.forEach(function (role) {
        var option = make("option", null, role.label);
        option.value = role.id;
        if (state.roles[col] === role.id) option.selected = true;
        select.appendChild(option);
      });
      select.addEventListener("change", function () {
        state.roles[col] = select.value;
        state.checked = null;
        el.add.hidden = true;
        setStatus("Mapping changed. Check the data again.");
      });
      cell.appendChild(select);
      tr.appendChild(cell);
      table.appendChild(tr);
    });
    el.body.appendChild(table);
    el.preview = make("div", "te-import__preview");
    el.body.appendChild(el.preview);
    el.check.hidden = false;
    el.add.hidden = true;
    setStatus("Check the mapping, then validate the data.");
  }

  function configureColumns() {
    var rows = state.rows;
    var width = 0;
    rows.slice(0, 200).forEach(function (row) { if (row.length > width) width = row.length; });
    state.hasHeader = state.hasHeader !== undefined ? state.hasHeader : firstRowIsHeader(rows);
    state.body = state.hasHeader ? rows.slice(1) : rows;
    state.header = [];
    var i;
    for (i = 0; i < width; i++) {
      state.header.push(state.hasHeader && rows[0][i] !== undefined ? rows[0][i] : "Column " + (i + 1));
    }
    var preset = state.hasHeader ? loadPreset(state.header) : null;
    state.roles = preset || detectRoles(state.header, state.body);
    state.presetLoaded = !!preset;
  }

  function handleFile(file) {
    if (!file) return;
    if (file.size > MAX_BYTES) {
      setStatus("That file is over " + Math.round(MAX_BYTES / 1048576) + " MB.", "error");
      return;
    }
    setStatus("Reading " + file.name + "\u2026");
    var reader = new window.FileReader();
    reader.onerror = function () { setStatus("Could not read that file.", "error"); };
    reader.onload = function () {
      var rows = parseFile(file.name, String(reader.result || ""));
      if (rows.length < 1) {
        setStatus("No rows found in that file.", "error");
        return;
      }
      if (rows.length > MAX_ROWS + 1) rows = rows.slice(0, MAX_ROWS + 1);
      state = { name: file.name, rows: rows, hasHeader: undefined };
      configureColumns();
      el.drop.hidden = true;
      renderMapper();
      if (state.presetLoaded) setStatus("Loaded the saved mapping for these columns. Check it, then validate the data.");
    };
    reader.readAsText(file);
  }

  function showReport(report, siteCount, walletCount) {
    clear(el.preview);
    el.preview.appendChild(make("h4", "te-import__h", "Result of the check"));
    var list = make("ul", "te-import__stats");
    list.appendChild(make("li", null, report.used + " of " + report.rows + " rows will add something to the graph."));
    list.appendChild(make("li", null, siteCount + " unique sites and " + walletCount + " unique wallets were checked."));
    Object.keys(report.counts).sort().forEach(function (type) {
      list.appendChild(make("li", null, report.counts[type] + " " + type.replace(/_/g, " ") + " nodes"));
    });
    el.preview.appendChild(list);
    if (report.issueRows) {
      el.preview.appendChild(make("h4", "te-import__h",
        report.issueRows + (report.issueRows === 1 ? " row had problems" : " rows had problems") + (report.issueRows > report.issues.length ? " (first " + report.issues.length + " shown)" : "")));
      var issues = make("ul", "te-import__issues");
      report.issues.forEach(function (text) { issues.appendChild(make("li", null, text)); });
      el.preview.appendChild(issues);
      el.preview.appendChild(make("p", "te-import__note", "Valid values on those rows are still imported; only the bad values are dropped."));
    }
  }

  function runCheck() {
    if (!state) return;
    var hasEntity = state.roles.some(function (role) { return role !== "ignore" && role !== "wallet_chain"; });
    if (!hasEntity) {
      setStatus("Map at least one column to something other than Ignore.", "warn");
      return;
    }
    if (state.roles.indexOf("wallet_chain") !== -1 && state.roles.indexOf("wallet_address") === -1) {
      setStatus("A chain column needs a wallet address column.", "warn");
      return;
    }
    if (state.hasHeader) savePreset(state.header, state.roles);

    el.check.disabled = true;
    el.add.hidden = true;
    var prepared = prepare(state.body, state.roles, state.hasHeader ? 1 : 0);
    setStatus("Checking " + prepared.siteList.length + " sites and " + prepared.walletList.length + " wallets\u2026");
    normaliseAll(prepared.siteList, prepared.walletList, function (done, total) {
      setStatus("Checked " + done + " of " + total + " batches\u2026");
    }).then(function (lookups) {
      var layer = window.TitanEye.uniqueLayerName("file:" + state.name);
      var built = build(prepared.items, state.roles, layer, state.name, lookups);
      state.checked = built;
      state.layer = layer;
      showReport(built.report, prepared.siteList.length, prepared.walletList.length);
      var addable = built.fragment.nodes.length;
      el.add.hidden = !addable;
      setStatus(addable
        ? "Ready: " + addable + " nodes and " + built.fragment.edges.length + " edges."
        : "Nothing in this file could be added.", addable ? "ok" : "warn");
    }).catch(function (err) {
      setStatus(err.message, "error");
    }).then(function () {
      el.check.disabled = false;
    });
  }

  function runAdd() {
    if (!state || !state.checked) return;
    var fragment = state.checked.fragment;
    if (fragment.nodes.length > WARN_NODES &&
        !window.confirm("This adds " + fragment.nodes.length + " nodes. The graph may be slow to lay out. Continue?")) {
      return;
    }
    window.TitanEye.addFragment(fragment, state.layer);
    close();
  }

  function open() {
    if (!el.root) return;
    reset();
    el.root.hidden = false;
    el.file.focus();
  }

  function close() {
    if (!el.root) return;
    el.root.hidden = true;
    state = null;
    if (opts.onClose) opts.onClose();
  }

  function init(options) {
    opts = options || {};
    el.root = document.getElementById("te-import");
    if (!el.root || !window.FileReader || !window.TitanEye) return false;
    el.file = document.getElementById("te-file");
    el.drop = document.getElementById("te-drop");
    el.body = document.getElementById("te-import-body");
    el.status = document.getElementById("te-import-status");
    el.check = document.getElementById("te-import-check");
    el.add = document.getElementById("te-import-add");

    el.file.addEventListener("change", function () { handleFile(el.file.files[0]); });
    ["dragenter", "dragover"].forEach(function (name) {
      el.drop.addEventListener(name, function (event) {
        event.preventDefault();
        el.drop.classList.add("is-over");
      });
    });
    ["dragleave", "drop"].forEach(function (name) {
      el.drop.addEventListener(name, function (event) {
        event.preventDefault();
        el.drop.classList.remove("is-over");
      });
    });
    el.drop.addEventListener("drop", function (event) {
      var files = event.dataTransfer && event.dataTransfer.files;
      if (files && files.length) handleFile(files[0]);
    });
    el.check.addEventListener("click", runCheck);
    el.add.addEventListener("click", runAdd);
    document.getElementById("te-import-close").addEventListener("click", close);
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && !el.root.hidden) {
        event.stopImmediatePropagation();
        close();
      }
    }, true);
    return true;
  }

  return { init: init, open: open, close: close };
})();
