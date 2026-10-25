/*
 * TitanEye: map one scan onto the graph (phase 6).
 *
 * A search hit only carries a handful of fields. This module pulls the full urlscan result for a
 * scan (POST /api/graph/site) and offers what it holds: file hashes, requested filenames,
 * third-party domains and the IPs behind them, the TLS certificate, technologies, Telegram
 * contacts, wallets in links, brands, tags and redirect hops.
 *
 * Two ways in, both ending at the same checklist:
 *   - the site node's detail panel: "Pull scan and map details";
 *   - TitanEyeScan.addScan(uuid), used by the results grid and the analyzer buttons: it opens the
 *     graph, adds the site with its apex, IP, ASN and reverse DNS, selects it, and leaves the
 *     checklist ready so nothing else lands on the graph until you tick it.
 *
 * Exposes window.TitanEyeScan { init, addScan }.
 */
window.TitanEyeScan = (function () {
  "use strict";

  var LAYER = "urlscan";
  var PREF_KEY = "titaneye.scan.categories";
  var LINK_ONLY_KEY = "titaneye.scan.linkOnly";
  var CONFIRM_NODES = 300;
  var UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

  var CATEGORIES = [
    ["hashes", "File hashes", true],
    ["filenames", "Filenames", true],
    ["domains", "Third-party domains", true],
    ["ips", "IPs behind those domains", true],
    ["cert", "TLS certificate", true],
    ["contacts", "Telegram contacts", true],
    ["wallets", "Wallets in links", true],
    ["brands", "Brands", true],
    ["tags", "Tags", true],
    ["tech", "Technologies", false],
    ["redirects", "Redirect hops", false]
  ];

  var SKIPPED = {
    empty_body_hash: "files with an empty body",
    unrecognised_hash: "hashes that were not SHA-256",
    hashes_over_cap: "hashes beyond the cap of 100",
    filenames_over_cap: "filenames beyond the cap of 100",
    domains_over_cap: "domains beyond the cap of 100",
    ips_over_cap: "IPs beyond the cap of 100",
    redirects_over_cap: "redirects beyond the cap of 10",
    bad_domain: "domains that failed validation",
    wallet_failed_validation: "wallet-like strings that failed validation"
  };

  var core = null;
  var previews = {};   /* scan id -> {fragment, meta, siteId} */
  var chosen = {};     /* site node id -> scan id picked in the select */
  var ticked = null;   /* category -> bool, loaded once from localStorage */
  var linkOnly = null; /* true: add only lines to nodes already on the graph, no new nodes */
  var busy = false;

  function make(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  /* ------------------------------------------------------------ preferences */

  function loadTicks() {
    if (ticked) return ticked;
    ticked = {};
    CATEGORIES.forEach(function (c) { ticked[c[0]] = c[2]; });
    try {
      var saved = JSON.parse(window.localStorage.getItem(PREF_KEY) || "{}");
      CATEGORIES.forEach(function (c) {
        if (typeof saved[c[0]] === "boolean") ticked[c[0]] = saved[c[0]];
      });
    } catch (err) { /* storage blocked or corrupt: keep the defaults */ }
    try { linkOnly = window.localStorage.getItem(LINK_ONLY_KEY) === "1"; } catch (err) { linkOnly = false; }
    return ticked;
  }

  function saveTicks() {
    try { window.localStorage.setItem(PREF_KEY, JSON.stringify(ticked)); } catch (err) { /* ignore */ }
    try { window.localStorage.setItem(LINK_ONLY_KEY, linkOnly ? "1" : "0"); } catch (err) { /* ignore */ }
  }

  /* ----------------------------------------------------------------- fetch */

  function pull(scanId) {
    return core.api("POST", "/api/graph/site", { scan_id: scanId }).then(function (data) {
      var preview = { fragment: { nodes: data.nodes || [], edges: data.edges || [] }, meta: data.meta || {} };
      previews[scanId.toLowerCase()] = preview;
      return preview;
    });
  }

  /*
   * Merge the core part (and any ticked categories) of a preview into the graph. With onlyExisting,
   * nothing new is created: a node is kept only if it is already on the graph, and an edge only
   * if both of its ends are, so the scan adds lines between things you already have.
   */
  function apply(preview, categories, onlyExisting) {
    var wanted = {};
    categories.forEach(function (name) { wanted[name] = true; });
    var graph = core.graph();
    var present = function (id) { return !!(graph && graph.hasNode(id)); };
    var include = function (item) { return item.category === "core" || wanted[item.category]; };
    var fragment = {
      nodes: preview.fragment.nodes.filter(function (n) {
        return include(n) && (!onlyExisting || present(n.id));
      }),
      edges: preview.fragment.edges.filter(function (e) {
        return include(e) && (!onlyExisting || (present(e.source) && present(e.target)));
      })
    };
    var siteId = preview.meta.site;
    var before = core.graph() ? core.graph().order : 0;
    var added = core.merge(fragment, siteId, LAYER);
    core.updateCounts();
    core.runLayout();
    return { added: added, first: before === 0 };
  }

  function describeSkipped(meta) {
    var skipped = meta.skipped || {};
    var parts = Object.keys(skipped).map(function (reason) {
      return skipped[reason] + " " + (SKIPPED[reason] || reason.replace(/_/g, " "));
    });
    return parts.length ? "Left out: " + parts.join("; ") + "." : "";
  }

  /* --------------------------------------------------------- detail section */

  function countNew(preview, name) {
    var graph = core.graph();
    var fresh = 0;
    preview.fragment.nodes.forEach(function (n) {
      if (n.category === name && !(graph && graph.hasNode(n.id))) fresh += 1;
    });
    return fresh;
  }

  function countPresent(preview, name) {
    var graph = core.graph();
    var here = 0;
    preview.fragment.nodes.forEach(function (n) {
      if (n.category === name && graph && graph.hasNode(n.id)) here += 1;
    });
    return here;
  }

  function checklist(preview, note, siteId) {
    var box = make("div", "te-scan__list");
    var ticks = loadTicks();
    var boxes = {};
    var counts = preview.meta.categories || {};
    var anyRow = false;

    var only = make("label", "te-import__check");
    var onlyInput = make("input");
    onlyInput.type = "checkbox";
    onlyInput.checked = !!linkOnly;
    onlyInput.addEventListener("change", function () {
      linkOnly = onlyInput.checked;
      saveTicks();
      core.rerenderDetail();
    });
    only.appendChild(onlyInput);
    only.appendChild(make("span", null, "Only add lines to nodes already on the graph (no new nodes)"));
    box.appendChild(only);

    CATEGORIES.forEach(function (c) {
      var name = c[0];
      var total = counts[name] || 0;
      if (!total) return;
      anyRow = true;
      var label = make("label", "te-import__check");
      var input = make("input");
      input.type = "checkbox";
      input.checked = !!ticks[name];
      input.addEventListener("change", function () { ticks[name] = input.checked; saveTicks(); });
      boxes[name] = input;
      label.appendChild(input);
      var fresh = countNew(preview, name);
      var detail = linkOnly
        ? countPresent(preview, name) + " already on the graph"
        : total + (fresh !== total ? ", " + fresh + " new" : "");
      label.appendChild(make("span", null, c[1] + " (" + detail + ")"));
      box.appendChild(label);
    });

    if (!anyRow) {
      box.appendChild(make("p", "te-note", "This scan has no extra indicators beyond the site itself."));
      return box;
    }

    var add = make("button", "btn btn--primary btn--small", "Add selected to graph");
    add.type = "button";
    add.addEventListener("click", function () {
      var names = CATEGORIES.map(function (c) { return c[0]; }).filter(function (n) { return boxes[n] && boxes[n].checked; });
      var nodeTotal = linkOnly ? 0 : names.reduce(function (sum, n) { return sum + countNew(preview, n); }, 0);
      if (nodeTotal > CONFIRM_NODES && !window.confirm("This adds about " + nodeTotal + " nodes. Continue?")) return;
      var result = apply(preview, names, linkOnly);
      core.setStatus(
        "Mapped scan " + preview.meta.scan_id.slice(0, 8) + ": " + result.added.nodes + " new nodes, " +
        result.added.edges + " new edges." +
        (linkOnly && !result.added.edges ? " None of the scan's indicators were already on the graph." : ""),
        result.added.nodes || result.added.edges ? "ok" : "warn"
      );
      core.select(siteId);
      core.rerenderDetail();
    });
    box.appendChild(add);
    var skippedNote = describeSkipped(preview.meta);
    if (skippedNote) box.appendChild(make("p", "te-note", skippedNote));
    if (note) box.appendChild(make("p", "te-note", note));
    return box;
  }

  function buildSection(info) {
    if (info.type !== "site") return null;
    var scans = Array.isArray(info.data.scans) ? info.data.scans : [];
    var section = make("div", "te-section");
    section.appendChild(make("h3", "te-section__title", "Scan details"));

    var scanId = chosen[info.id] || scans[0] || "";
    var line = make("div", "te-field-row");
    var typed = null;
    if (scans.length > 1) {
      var pick = make("select", "field");
      scans.forEach(function (uuid, index) {
        var option = make("option", null, (index === 0 ? "Newest: " : "") + uuid.slice(0, 8) + "…");
        option.value = uuid;
        if (uuid === scanId) option.selected = true;
        pick.appendChild(option);
      });
      pick.addEventListener("change", function () { chosen[info.id] = pick.value; core.rerenderDetail(); });
      line.appendChild(pick);
    } else if (!scans.length) {
      typed = make("input", "field");
      typed.type = "text";
      typed.placeholder = "Scan ID (no scan is known for this site)";
      typed.spellcheck = false;
      typed.autocomplete = "off";
      line.appendChild(typed);
    }
    var button = make("button", "btn btn--small", previews[String(scanId).toLowerCase()] ? "Pull again" : "Pull scan and map details");
    button.type = "button";
    button.disabled = busy;
    button.addEventListener("click", function () {
      var id = (typed ? typed.value : scanId).trim();
      if (!UUID.test(id)) {
        core.setStatus("Enter a urlscan scan ID (36 characters).", "warn");
        return;
      }
      busy = true;
      button.disabled = true;
      core.setStatus("Pulling scan " + id.slice(0, 8) + " from urlscan.io…");
      pull(id).then(function (preview) {
        if (typed) {
          /* A typed scan ID is only trusted for this site if it is attached to it. */
          var data = core.graph().getNodeAttribute(info.id, "data") || {};
          core.setNodeData(info.id, "scans", (data.scans || []).concat([id.toLowerCase()]));
        }
        chosen[info.id] = id.toLowerCase();
        core.setStatus("Scan pulled. Choose what to add below.", "ok");
      }).catch(function (err) {
        core.setStatus(err.message, "error");
      }).then(function () {
        busy = false;
        core.rerenderDetail();
      });
    });
    line.appendChild(button);
    section.appendChild(line);

    var preview = previews[String(scanId).toLowerCase()];
    if (preview) {
      var note = preview.meta.site !== info.id
        ? "This scan is of " + preview.meta.site.replace(/^site:/, "") + ", not this site."
        : "";
      section.appendChild(checklist(preview, note, info.id));
    } else {
      section.appendChild(make("p", "te-note", "Uses your urlscan key. Nothing is added until you tick it."));
    }
    return section;
  }

  /* ------------------------------------------------------- grid / analyzer */

  /*
   * Open the graph, add the scan's site with its core hosting nodes, select it and leave the
   * indicator checklist open in the detail panel.
   */
  function addScan(scanId) {
    var id = String(scanId || "").trim().toLowerCase();
    if (!window.TitanEye || !core) return Promise.resolve(null);
    window.TitanEye.open();
    if (!UUID.test(id)) {
      core.setStatus("That is not a urlscan scan ID.", "warn");
      return Promise.resolve(null);
    }
    core.setStatus("Pulling scan " + id.slice(0, 8) + " from urlscan.io…");
    return pull(id).then(function (preview) {
      var result = apply(preview, []);
      var siteId = preview.meta.site;
      chosen[siteId] = id;
      core.select(siteId);
      core.focusNode(siteId);
      core.setStatus(
        "Added " + siteId.replace(/^site:/, "") + " (" + result.added.nodes + " new nodes). " +
        "Tick the indicators to map in the panel on the right.", "ok"
      );
      return siteId;
    }).catch(function (err) {
      core.setStatus(err.message, "error");
      return null;
    });
  }

  function init() {
    if (!window.TitanEye || !window.TitanEye.core) return false;
    core = window.TitanEye.core;
    core.addDetailSection(buildSection);
    return true;
  }

  return { init: init, addScan: addScan };
})();
