/* TitanEye cases and exports.
 *
 * A case is the graph on screen (nodes, edges, positions, notes of where each
 * thing came from, which datasets are switched on). Cases live in IndexedDB in
 * this browser and can be downloaded as a JSON file and loaded back.
 *
 * Case files and every export contain graph data only. Provider keys and the
 * urlscan and Scambusters keys are never part of the graph, so they cannot end
 * up in a file. CSV cells that start with = + - @ tab or CR are prefixed with a
 * quote so a spreadsheet will not run them as formulas.
 */
window.TitanEyeCases = (function () {
  "use strict";

  var DB_NAME = "titaneye";
  var DB_VERSION = 1;
  var FILE_APP = "TitanEye";
  var FILE_VERSION = 1;
  var MAX_FILE_BYTES = 100 * 1024 * 1024;
  var MAX_WALLETS_PER_REPORT = 30;

  var core = null;
  var el = {};

  function make(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function say(message, tone) {
    el.status.textContent = message;
    el.status.className = "te-import__status" + (tone ? " te-import__status--" + tone : "");
  }

  function stamp() {
    return new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
  }

  function safeName(text) {
    return String(text || "titaneye").replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 60) || "titaneye";
  }

  /* ----------------------------------------------------------- IndexedDB */

  function openDb(done) {
    var request;
    try {
      request = window.indexedDB.open(DB_NAME, DB_VERSION);
    } catch (err) {
      done(new Error("This browser is not allowing saved cases (private mode or blocked storage). Download the case file instead."));
      return;
    }
    request.onupgradeneeded = function () {
      var db = request.result;
      db.createObjectStore("cases", { keyPath: "id", autoIncrement: true });
      db.createObjectStore("graphs", { keyPath: "id" });
    };
    request.onsuccess = function () { done(null, request.result); };
    request.onerror = function () {
      done(new Error("Could not open the saved-case store in this browser."));
    };
    request.onblocked = request.onerror;
  }

  function withDb(work, done) {
    openDb(function (err, db) {
      if (err) { done(err); return; }
      work(db, function (error, value) {
        db.close();
        done(error, value);
      });
    });
  }

  function saveCase(name, snapshot, done) {
    withDb(function (db, finish) {
      var tx = db.transaction(["cases", "graphs"], "readwrite");
      var meta = { name: name, saved_at: new Date().toISOString(), nodes: snapshot.nodes.length, edges: snapshot.edges.length };
      var add = tx.objectStore("cases").add(meta);
      add.onsuccess = function () {
        tx.objectStore("graphs").put({ id: add.result, graph: snapshot });
      };
      tx.oncomplete = function () { finish(null, meta); };
      tx.onerror = function () { finish(new Error("The browser refused to store this case (it may be too large).")); };
      tx.onabort = tx.onerror;
    }, done);
  }

  function listCases(done) {
    withDb(function (db, finish) {
      var request = db.transaction("cases", "readonly").objectStore("cases").getAll();
      request.onsuccess = function () { finish(null, request.result.reverse()); };
      request.onerror = function () { finish(new Error("Could not read saved cases.")); };
    }, done);
  }

  function getGraph(id, done) {
    withDb(function (db, finish) {
      var request = db.transaction("graphs", "readonly").objectStore("graphs").get(id);
      request.onsuccess = function () { finish(null, request.result && request.result.graph); };
      request.onerror = function () { finish(new Error("Could not read that case.")); };
    }, done);
  }

  function deleteCase(id, done) {
    withDb(function (db, finish) {
      var tx = db.transaction(["cases", "graphs"], "readwrite");
      tx.objectStore("cases").delete(id);
      tx.objectStore("graphs").delete(id);
      tx.oncomplete = function () { finish(null); };
      tx.onerror = function () { finish(new Error("Could not delete that case.")); };
    }, done);
  }

  /* ------------------------------------------------------------ downloads */

  function download(filename, text, type) {
    var blob = new Blob([text], { type: type + ";charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
  }

  function csvCell(value) {
    var text = value === null || value === undefined ? "" : String(value);
    if (/^[=+\-@\t\r]/.test(text)) text = "'" + text;
    if (/[",\n\r]/.test(text)) text = '"' + text.replace(/"/g, '""') + '"';
    return text;
  }

  function csv(header, rows) {
    var lines = [header.map(csvCell).join(",")];
    rows.forEach(function (row) { lines.push(row.map(csvCell).join(",")); });
    return "﻿" + lines.join("\r\n") + "\r\n";
  }

  function xml(text) {
    return String(text === null || text === undefined ? "" : text)
      .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f￾￿]/g, "")
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&apos;");
  }

  /* -------------------------------------------------------------- exports */

  function onlyShown() {
    return !!el.shown.checked;
  }

  function nodeList() {
    var g = core.graph();
    var out = [];
    if (!g) return out;
    var shown = onlyShown();
    g.forEachNode(function (id, attrs) {
      if (shown && attrs.hidden) return;
      out.push({ id: id, attrs: attrs, data: attrs.data || {}, degree: g.degree(id) });
    });
    return out;
  }

  function edgeList() {
    var g = core.graph();
    var out = [];
    if (!g) return out;
    var shown = onlyShown();
    g.forEachEdge(function (id, attrs, source, target) {
      if (shown && (g.getNodeAttribute(source, "hidden") || g.getNodeAttribute(target, "hidden"))) return;
      out.push({ id: id, attrs: attrs, data: attrs.data || {}, source: source, target: target });
    });
    return out;
  }

  function exportNodes() {
    var rows = nodeList().map(function (n) {
      var d = n.data;
      var onchain = d.onchain || {};
      var chains = Object.keys(onchain);
      var first = chains.length ? onchain[chains[0]].summary : null;
      return [n.id, n.attrs.ntype, n.attrs.full, n.degree, d.first_seen, d.last_seen,
              (d.layers || []).join(" "), (d.chains || []).join(" "), d.country, d.status, d.domain_age_days,
              (d.scans || []).join(" "),
              first ? first.provider : "", first ? first.balance + " " + first.native_symbol : "",
              first ? first.first_seen : "", first ? first.last_seen : "", first ? first.queried_at : ""];
    });
    download("titaneye-nodes-" + stamp() + ".csv", csv(
      ["id", "type", "value", "connections", "first_seen", "last_seen", "datasets", "chains", "country", "status",
       "domain_age_days", "scan_ids", "onchain_provider", "onchain_balance", "onchain_first_seen", "onchain_last_seen",
       "onchain_queried_at"], rows), "text/csv");
    say(rows.length + " nodes exported.", "ok");
  }

  function exportEdges() {
    var rows = edgeList().map(function (e) {
      return [e.id, e.source, e.target, e.attrs.etype, e.data.source, e.data.first_seen, e.data.last_seen, e.data.row];
    });
    download("titaneye-edges-" + stamp() + ".csv", csv(
      ["id", "source", "target", "type", "provenance", "first_seen", "last_seen", "row"], rows), "text/csv");
    say(rows.length + " edges exported.", "ok");
  }

  /* One row per indicator an analyst would block or report. */
  function exportIocs() {
    var seen = {};
    var rows = [];
    function add(type, value, context) {
      var key = type + "|" + value;
      if (!value || seen[key]) return;
      seen[key] = true;
      rows.push([type, value, context || ""]);
    }
    nodeList().forEach(function (n) {
      var value = n.attrs.full;
      switch (n.attrs.ntype) {
        case "site": add("domain", value, "site"); break;
        case "apex_domain": add("domain", value, "apex"); break;
        case "third_party": add("domain", value, "third party"); break;
        case "ip": add("ip", value, ""); break;
        case "cidr": add("ip_range", value, ""); break;
        case "file_hash": add("sha256", value, ""); break;
        case "wallet": add("wallet", value, (n.data.chains || []).join(" ")); break;
        case "contact": add("telegram", value, ""); break;
        default: break;
      }
    });
    rows.sort(function (a, b) { return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : 1; });
    download("titaneye-iocs-" + stamp() + ".csv", csv(["type", "value", "context"], rows), "text/csv");
    say(rows.length + " indicators exported.", "ok");
  }

  function exportGraphml() {
    var parts = ['<?xml version="1.0" encoding="UTF-8"?>',
      '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
      '<key id="k_type" for="node" attr.name="type" attr.type="string"/>',
      '<key id="k_label" for="node" attr.name="label" attr.type="string"/>',
      '<key id="k_sets" for="node" attr.name="datasets" attr.type="string"/>',
      '<key id="k_etype" for="edge" attr.name="type" attr.type="string"/>',
      '<key id="k_prov" for="edge" attr.name="provenance" attr.type="string"/>',
      '<graph id="titaneye" edgedefault="directed">'];
    var nodes = nodeList();
    var included = {};
    nodes.forEach(function (n) {
      included[n.id] = true;
      parts.push('<node id="' + xml(n.id) + '"><data key="k_type">' + xml(n.attrs.ntype) + '</data><data key="k_label">' +
        xml(n.attrs.full) + '</data><data key="k_sets">' + xml((n.data.layers || []).join(" ")) + '</data></node>');
    });
    var count = 0;
    edgeList().forEach(function (e) {
      if (!included[e.source] || !included[e.target]) return;
      count += 1;
      parts.push('<edge id="e' + count + '" source="' + xml(e.source) + '" target="' + xml(e.target) +
        '"><data key="k_etype">' + xml(e.attrs.etype) + '</data><data key="k_prov">' + xml(e.data.source) + '</data></edge>');
    });
    parts.push("</graph>", "</graphml>");
    download("titaneye-graph-" + stamp() + ".graphml", parts.join("\n"), "application/graphml+xml");
    say(nodes.length + " nodes and " + count + " edges exported as GraphML.", "ok");
  }

  /* ---------------------------------------------------------- case files */

  function caseFile(name, snapshot) {
    return JSON.stringify({ app: FILE_APP, schema_version: FILE_VERSION, name: name,
                            saved_at: new Date().toISOString(), graph: snapshot });
  }

  function validSnapshot(graph) {
    return !!graph && typeof graph === "object" && Array.isArray(graph.nodes) && Array.isArray(graph.edges);
  }

  function importFile(file) {
    if (!file) return;
    if (file.size > MAX_FILE_BYTES) {
      say("That file is over " + Math.round(MAX_FILE_BYTES / 1048576) + " MB.", "error");
      return;
    }
    var reader = new window.FileReader();
    reader.onerror = function () { say("Could not read that file.", "error"); };
    reader.onload = function () {
      var parsed;
      try {
        parsed = JSON.parse(String(reader.result));
      } catch (err) {
        say("That file is not valid JSON.", "error");
        return;
      }
      if (!parsed || parsed.app !== FILE_APP || !validSnapshot(parsed.graph)) {
        say("That is not a TitanEye case file.", "error");
        return;
      }
      if (parsed.schema_version > FILE_VERSION) {
        say("That case was saved by a newer version of TitanEye.", "error");
        return;
      }
      if (core.graph() && core.graph().order && !window.confirm("Replace the graph on screen with this case?")) return;
      var result = core.loadSnapshot(parsed.graph);
      say("Loaded " + result.nodes + " nodes and " + result.edges + " edges from the file.", "ok");
    };
    reader.readAsText(file);
  }

  /* ------------------------------------------------------------------- UI */

  function renderList(cases) {
    while (el.list.firstChild) el.list.removeChild(el.list.firstChild);
    if (!cases.length) {
      el.list.appendChild(make("p", "te-note", "No saved cases in this browser yet."));
      return;
    }
    var table = make("table", "te-import__table");
    cases.forEach(function (c) {
      var tr = make("tr");
      var title = make("td");
      title.appendChild(make("strong", null, c.name));
      title.appendChild(make("div", "te-note", c.saved_at.slice(0, 16).replace("T", " ") + " UTC, " + c.nodes + " nodes, " + c.edges + " edges"));
      tr.appendChild(title);
      var actions = make("td", "te-cases__actions");
      var load = make("button", "btn btn--small", "Load");
      load.type = "button";
      load.addEventListener("click", function () {
        getGraph(c.id, function (err, graph) {
          if (err || !validSnapshot(graph)) { say(err ? err.message : "That case could not be read.", "error"); return; }
          if (core.graph() && core.graph().order && !window.confirm("Replace the graph on screen with \"" + c.name + "\"?")) return;
          var result = core.loadSnapshot(graph);
          say("Loaded " + c.name + ": " + result.nodes + " nodes, " + result.edges + " edges.", "ok");
        });
      });
      var save = make("button", "btn btn--ghost btn--small", "Download");
      save.type = "button";
      save.addEventListener("click", function () {
        getGraph(c.id, function (err, graph) {
          if (err || !validSnapshot(graph)) { say(err ? err.message : "That case could not be read.", "error"); return; }
          download("titaneye-case-" + safeName(c.name) + "-" + stamp() + ".json", caseFile(c.name, graph), "application/json");
        });
      });
      var del = make("button", "btn btn--ghost btn--small", "Delete");
      del.type = "button";
      del.addEventListener("click", function () {
        if (!window.confirm("Delete the saved case \"" + c.name + "\"?")) return;
        deleteCase(c.id, function (err) {
          if (err) say(err.message, "error"); else refreshList();
        });
      });
      actions.appendChild(load);
      actions.appendChild(save);
      actions.appendChild(del);
      tr.appendChild(actions);
      table.appendChild(tr);
    });
    el.list.appendChild(table);
  }

  function refreshList() {
    listCases(function (err, cases) {
      if (err) {
        while (el.list.firstChild) el.list.removeChild(el.list.firstChild);
        el.list.appendChild(make("p", "te-note", err.message));
        return;
      }
      renderList(cases);
    });
  }

  function saveCurrent() {
    var g = core.graph();
    if (!g || !g.order) { say("The graph is empty, so there is nothing to save.", "warn"); return; }
    var name = (el.name.value || "").trim() || ("Case " + stamp());
    saveCase(name.slice(0, 80), core.snapshot(), function (err) {
      if (err) { say(err.message, "error"); return; }
      el.name.value = "";
      say("Saved \"" + name + "\" in this browser.", "ok");
      refreshList();
    });
  }

  function downloadCurrent() {
    var g = core.graph();
    if (!g || !g.order) { say("The graph is empty.", "warn"); return; }
    var name = (el.name.value || "").trim() || "titaneye";
    download("titaneye-case-" + safeName(name) + "-" + stamp() + ".json", caseFile(name, core.snapshot()), "application/json");
    say("Case file downloaded.", "ok");
  }

  function open() {
    el.root.hidden = false;
    say("");
    refreshList();
    el.name.focus();
  }

  function close() {
    el.root.hidden = true;
  }

  /* A site node's own button: report it with the wallets linked to it. */
  function reportSection(ctx) {
    var reporter = window.ScambustersReporter;
    if (ctx.type !== "site" || !reporter) return null;
    var g = core.graph();
    var wallets = [];
    g.forEachNeighbor(ctx.id, function (other, attrs) {
      if (attrs.ntype !== "wallet" || wallets.length >= MAX_WALLETS_PER_REPORT) return;
      var chains = (attrs.data && attrs.data.chains) || [];
      wallets.push({ address: attrs.full, chain: chains[0] || "" });
    });
    var box = make("div", "te-section");
    box.appendChild(make("h3", "te-section__title", "Scambusters"));
    var button = make("button", "btn btn--small",
      wallets.length ? "Report site and " + wallets.length + " wallet" + (wallets.length === 1 ? "" : "s") : "Report site");
    button.type = "button";
    button.addEventListener("click", function () {
      var url = ctx.data.scanned_url || ("https://" + ctx.value + "/");
      reporter.open({ siteUrl: url, wallets: wallets });
    });
    box.appendChild(button);
    box.appendChild(make("p", "te-note",
      "Opens the report form filled in. Up to " + MAX_WALLETS_PER_REPORT + " wallets go in one submission, and you review it before sending."));
    return box;
  }

  function init() {
    core = window.TitanEye && window.TitanEye.core;
    el.root = document.getElementById("te-cases");
    var openButton = document.getElementById("te-cases-open");
    if (!core || !el.root || !openButton) return false;
    el.name = document.getElementById("te-case-name");
    el.list = document.getElementById("te-case-list");
    el.status = document.getElementById("te-cases-status");
    el.shown = document.getElementById("te-export-shown");
    openButton.addEventListener("click", open);
    document.getElementById("te-cases-close").addEventListener("click", close);
    document.getElementById("te-case-save").addEventListener("click", saveCurrent);
    document.getElementById("te-case-download").addEventListener("click", downloadCurrent);
    document.getElementById("te-case-file").addEventListener("change", function (event) {
      importFile(event.target.files[0]);
      event.target.value = "";
    });
    document.getElementById("te-export-nodes").addEventListener("click", exportNodes);
    document.getElementById("te-export-edges").addEventListener("click", exportEdges);
    document.getElementById("te-export-iocs").addEventListener("click", exportIocs);
    document.getElementById("te-export-graphml").addEventListener("click", exportGraphml);
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && !el.root.hidden) {
        event.stopImmediatePropagation();
        close();
      }
    }, true);
    core.addDetailSection(reportSection);
    return true;
  }

  return { init: init, open: open, close: close,
           /* exposed for tests */ csvCell: csvCell, xml: xml };
})();
