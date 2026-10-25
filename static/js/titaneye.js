/* TitanEye: link-analysis graph workspace.
 *
 * Renders nodes and edges returned by /api/graph/expand with sigma.js (WebGL)
 * over a graphology graph, laid out with ForceAtlas2 in short chunks so the
 * page stays responsive. The node/edge contract is in docs/TITANEYE.md.
 *
 * All node labels and attributes come from scanned pages, so everything is
 * written with textContent. Nothing here builds HTML from data.
 */
window.TitanEye = (function () {
  "use strict";

  var TYPES = {
    site:         { label: "Site",         color: "#4ce1d2" },
    apex_domain:  { label: "Apex domain",  color: "#6ec8ff" },
    ip:           { label: "IP",           color: "#f2c94c" },
    cidr:         { label: "IP range",     color: "#e9a23b" },
    asn:          { label: "ASN",          color: "#c58bff" },
    ptr:          { label: "Reverse DNS",  color: "#9aa7ff" },
    tls_cert:     { label: "TLS issuer",   color: "#ff8a7a" },
    file_hash:    { label: "Hash",         color: "#7bd88f" },
    filename:     { label: "Filename",     color: "#98d8a0" },
    text_string:  { label: "Text",         color: "#ffb3d1" },
    third_party:  { label: "Third party",  color: "#ff9f43" },
    tech:         { label: "Technology",   color: "#b0bec5" },
    brand:        { label: "Brand",        color: "#ff6b81" },
    contact:      { label: "Contact",      color: "#5ce1ff" },
    wallet:       { label: "Wallet",       color: "#ffd166" },
    tag:          { label: "Tag",          color: "#a3e635" },
    "case":       { label: "Case",         color: "#ffffff" }
  };
  var DIM_COLOR = "#33415c";
  var EDGE_COLOR = "rgba(140, 170, 210, 0.2)";
  var EDGE_AUTO_THRESHOLD = 1500;   /* above this many nodes, edges show only around the selection */
  var MAX_LABEL = 28;
  var FIRST_LAYOUT_ITERATIONS = 150;
  var NEXT_LAYOUT_ITERATIONS = 80;

  var el = {};
  var opts = {};
  var state = {
    ready: false,
    graph: null,
    renderer: null,
    selected: null,
    neighbors: null,
    hiddenTypes: {},
    layers: {},
    time: { from: null, to: null },
    noiseMax: null,
    edgeMode: "auto",
    declutter: { on: false, min: 2, hidden: 0 },
    detailSections: [],
    selectListeners: [],
    undo: [],
    listeners: [],
    transforms: [],
    busy: false,
    layoutToken: 0,
    worker: null,
    cursors: {},
    lastKey: null,
    find: { active: false, matches: [], set: {}, index: -1, current: null }
  };

  function $(id) { return document.getElementById(id); }

  function make(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function clip(text, max) {
    text = String(text);
    return text.length > max ? text.slice(0, max - 1) + "…" : text;
  }

  /* ---------------------------------------------------------------- api */

  function api(method, path, body) {
    var headers = { "Accept": "application/json" };
    var key = opts.getKey ? opts.getKey() : "";
    if (key) headers["X-URLScan-Key"] = key;
    var init = { method: method, headers: headers };
    if (body) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    return fetch(path, init).then(function (response) {
      return response.json().then(function (data) {
        if (!response.ok || !data || data.ok === false) {
          var error = (data && data.error) || {};
          var failure = new Error(error.message || "Request failed (HTTP " + response.status + ").");
          failure.code = error.code;
          throw failure;
        }
        return data;
      }, function () {
        throw new Error("The server sent a reply that is not JSON (HTTP " + response.status + ").");
      });
    });
  }

  /* -------------------------------------------------------------- status */

  function setStatus(message, tone) {
    el.status.textContent = message;
    el.status.className = "te-status" + (tone ? " te-status--" + tone : "");
  }

  function setBusy(busy) {
    state.busy = busy;
    el.run.disabled = busy;
    el.more.disabled = busy;
  }

  /* --------------------------------------------------------------- graph */

  function ensureGraph() {
    if (state.graph) return;
    state.graph = new window.graphology({ multi: true, type: "directed" });
    state.renderer = new window.Sigma(state.graph, el.canvas, {
      labelRenderedSizeThreshold: 6,
      labelDensity: 0.7,
      labelColor: { color: "#dce8f8" },
      defaultEdgeColor: EDGE_COLOR,
      /* The panel is hidden when closed; a frame queued just before that must not throw. */
      allowInvalidContainer: true,
      zIndex: true,
      nodeReducer: reduceNode,
      edgeReducer: reduceEdge
    });
    /* Sigma always draws edges under nodes, so the selected node's lines are drawn again on
     * a transparent canvas above everything (see drawSelectionEdges). */
    el.overlay = document.createElement("canvas");
    el.overlay.className = "te-overlay";
    el.overlay.setAttribute("aria-hidden", "true");
    el.canvas.appendChild(el.overlay);
    state.renderer.on("afterRender", drawSelectionEdges);
    state.renderer.on("clickNode", function (event) { select(event.node); });
    state.renderer.on("clickStage", function () { select(null); });
    state.renderer.on("enterNode", function (event) { showTip(event.node); });
    state.renderer.on("leaveNode", hideTip);
    state.renderer.getCamera().on("updated", hideTip);
  }

  var SELECTION_EDGE_COLOR = "rgba(110, 200, 255, 0.85)";

  /* Lines from the selected node to its neighbours, on top of every node except the selected one. */
  function drawSelectionEdges() {
    var canvas = el.overlay;
    var g = state.graph;
    if (!canvas || !g || !state.renderer) return;
    var ratio = window.devicePixelRatio || 1;
    var width = el.canvas.clientWidth;
    var height = el.canvas.clientHeight;
    if (canvas.width !== Math.round(width * ratio) || canvas.height !== Math.round(height * ratio)) {
      canvas.width = Math.round(width * ratio);
      canvas.height = Math.round(height * ratio);
      canvas.style.width = width + "px";
      canvas.style.height = height + "px";
    }
    var ctx = canvas.getContext("2d");
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    ctx.clearRect(0, 0, width, height);
    var id = state.selected;
    if (!id || !g.hasNode(id) || state.find.active || edgeMode() === "none") return;
    if (g.getNodeAttribute(id, "hidden")) return;
    var from = state.renderer.graphToViewport({ x: g.getNodeAttribute(id, "x"), y: g.getNodeAttribute(id, "y") });
    ctx.strokeStyle = SELECTION_EDGE_COLOR;
    ctx.lineWidth = 2;
    ctx.beginPath();
    g.forEachEdge(id, function (edge, attrs, source, target) {
      if (attrs.hidden) return;
      var other = source === id ? target : source;
      if (other === id || g.getNodeAttribute(other, "hidden")) return;
      var to = state.renderer.graphToViewport({ x: g.getNodeAttribute(other, "x"), y: g.getNodeAttribute(other, "y") });
      ctx.moveTo(from.x, from.y);
      ctx.lineTo(to.x, to.y);
    });
    ctx.stroke();

    /* The lines go over the other nodes but not over the selected one: put its dot back on top. */
    var shown = state.renderer.getNodeDisplayData(id);
    if (shown) {
      ctx.fillStyle = shown.color;
      ctx.beginPath();
      ctx.arc(from.x, from.y, state.renderer.scaleSize(shown.size), 0, Math.PI * 2);
      ctx.fill();
    }
  }

  /* Hover tooltip with the full value; long values are clipped on the canvas. */
  function showTip(id) {
    var g = state.graph;
    if (!el.tip || !g || !g.hasNode(id)) return;
    var attrs = g.getNodeAttributes(id);
    var spot = state.renderer.graphToViewport({ x: attrs.x, y: attrs.y });
    el.tipValue.textContent = attrs.full;
    el.tipMeta.textContent = TYPES[attrs.ntype].label + ", " + g.degree(id) + " connection" + (g.degree(id) === 1 ? "" : "s");
    el.tip.style.left = Math.round(spot.x + 14) + "px";
    el.tip.style.top = Math.round(spot.y + 14) + "px";
    el.tip.hidden = false;
  }

  function hideTip() {
    if (el.tip) el.tip.hidden = true;
  }

  /* Fewer, bigger-node labels as the graph grows, so they stop piling up. */
  function applyLabelSettings() {
    if (!state.renderer || !state.graph) return;
    var n = state.graph.order;
    var cfg = n < 200 ? { t: 4, d: 1, c: 80 } : (n < 2000 ? { t: 6, d: 0.6, c: 100 } : { t: 9, d: 0.35, c: 140 });
    state.renderer.setSetting("labelRenderedSizeThreshold", cfg.t);
    state.renderer.setSetting("labelDensity", cfg.d);
    state.renderer.setSetting("labelGridCellSize", cfg.c);
  }

  function edgeMode() {
    if (state.edgeMode !== "auto") return state.edgeMode;
    return state.graph && state.graph.order > EDGE_AUTO_THRESHOLD ? "selection" : "all";
  }

  function hiddenEdge(data) {
    return { color: data.color, size: data.size, hidden: true };
  }

  /* While the find bar has a query, matches stand out and everything else
   * dims; that takes priority over the neighbour dimming of a selection. */
  function reduceNode(node, data) {
    var finding = state.find.active;
    if (!state.selected && !finding) return data;
    var out = {};
    var key;
    for (key in data) if (Object.prototype.hasOwnProperty.call(data, key)) out[key] = data[key];
    if (finding) {
      if (state.find.set[node]) {
        out.forceLabel = true;
        out.size = data.size + (node === state.find.current ? 5 : 2);
        out.zIndex = node === state.find.current ? 3 : 2;
      } else {
        out.color = DIM_COLOR;
        out.label = "";
      }
    }
    if (node === state.selected) {
      out.forceLabel = true;
      out.size = data.size + 3;
      out.zIndex = 3;
    } else if (!finding && state.selected && !state.neighbors[node]) {
      out.color = DIM_COLOR;
      out.label = "";
    }
    return out;
  }

  function reduceEdge(edge, data) {
    var mode = edgeMode();
    if (mode === "none") return hiddenEdge(data);
    var onlyAround = mode === "selection";
    var pair;
    if (state.find.active) {
      pair = state.graph.extremities(edge);
      if (state.find.set[pair[0]] && state.find.set[pair[1]]) return data;
      return onlyAround ? hiddenEdge(data) : { color: "rgba(80, 100, 130, 0.1)", size: 1, hidden: data.hidden };
    }
    if (!state.selected) return onlyAround ? hiddenEdge(data) : data;
    pair = state.graph.extremities(edge);
    if (pair[0] === state.selected || pair[1] === state.selected) {
      /* Drawn by drawSelectionEdges, above the nodes. */
      return hiddenEdge(data);
    }
    return onlyAround ? hiddenEdge(data) : { color: "rgba(80, 100, 130, 0.12)", size: 1, hidden: data.hidden };
  }

  /* Sizes are screen pixels, so big graphs need smaller dots to stay readable. */
  function sizeScale(order) {
    if (order < 500) return 1;
    if (order < 3000) return 0.7;
    if (order < 10000) return 0.5;
    return 0.35;
  }

  function nodeSize(degree, order) {
    return Math.min(3 + Math.sqrt(degree) * 1.8, 26) * sizeScale(order);
  }

  function resizeAll() {
    var g = state.graph;
    g.updateEachNodeAttributes(function (id, attrs) {
      attrs.size = nodeSize(g.degree(id), g.order);
      return attrs;
    });
  }

  function mergeAttrs(target, incoming) {
    var key;
    for (key in incoming) {
      if (!Object.prototype.hasOwnProperty.call(incoming, key)) continue;
      var value = incoming[key];
      if (value === null || value === undefined) continue;
      if (Array.isArray(value) && Array.isArray(target[key])) {
        var merged = target[key].slice();
        var i;
        for (i = 0; i < value.length; i++) {
          if (merged.indexOf(value[i]) === -1) merged.push(value[i]);
        }
        target[key] = merged;
      } else if (key === "first_seen" && target[key]) {
        if (value < target[key]) target[key] = value;
      } else if (key === "last_seen" && target[key]) {
        if (value > target[key]) target[key] = value;
      } else {
        target[key] = value;
      }
    }
  }

  function placeNear(anchor) {
    var g = state.graph;
    var angle = Math.random() * Math.PI * 2;
    var radius = 4 + Math.random() * 16;
    if (anchor && g.hasNode(anchor)) {
      return {
        x: g.getNodeAttribute(anchor, "x") + Math.cos(angle) * radius,
        y: g.getNodeAttribute(anchor, "y") + Math.sin(angle) * radius
      };
    }
    return { x: Math.cos(angle) * radius * 6, y: Math.sin(angle) * radius * 6 };
  }

  /* Add a fragment from the server. Returns {nodes, edges} actually new. */
  function merge(fragment, anchor, layer) {
    ensureGraph();
    var g = state.graph;
    var added = { nodes: 0, edges: 0 };
    var journal = { kind: "add", nodes: [], edges: [], prev: {} };
    if (layer && !state.layers[layer]) state.layers[layer] = { hidden: false };

    (fragment.nodes || []).forEach(function (n) {
      if (!TYPES[n.type]) return;
      if (layer) {
        n.attrs = n.attrs || {};
        n.attrs.layers = [layer];
      }
      if (g.hasNode(n.id)) {
        var data = g.getNodeAttribute(n.id, "data");
        if (!journal.prev[n.id]) journal.prev[n.id] = copyData(data);
        mergeAttrs(data, n.attrs || {});
        g.setNodeAttribute(n.id, "data", data);
      } else {
        var spot = placeNear(anchor);
        g.addNode(n.id, {
          label: clip(n.label, MAX_LABEL),
          full: n.label,
          ntype: n.type,
          color: TYPES[n.type].color,
          size: 3,
          x: spot.x,
          y: spot.y,
          hidden: false,
          placed: false,
          data: n.attrs || {}
        });
        added.nodes += 1;
        journal.nodes.push(n.id);
      }
    });

    (fragment.edges || []).forEach(function (e) {
      if (!g.hasNode(e.source) || !g.hasNode(e.target)) return;
      if (g.hasEdge(e.id)) {
        var data = g.getEdgeAttribute(e.id, "data");
        mergeAttrs(data, e.attrs || {});
        g.setEdgeAttribute(e.id, "data", data);
        return;
      }
      g.addDirectedEdgeWithKey(e.id, e.source, e.target, {
        etype: e.type, size: 1, color: EDGE_COLOR, data: e.attrs || {}
      });
      added.edges += 1;
      journal.edges.push(e.id);
    });

    if (added.nodes || added.edges) {
      journal.label = "add " + added.nodes + " nodes and " + added.edges + " edges";
      pushUndo(journal);
    }
    resizeAll();
    refreshVisibility();
    return added;
  }

  /* ---------------------------------------------------------------- undo */

  var UNDO_LIMIT = 50;

  /* Attribute objects hold scalars and arrays of scalars, so one level of copying is enough. */
  function copyData(data) {
    var out = {};
    Object.keys(data || {}).forEach(function (key) {
      out[key] = Array.isArray(data[key]) ? data[key].slice() : data[key];
    });
    return out;
  }

  function updateUndoButton() {
    if (!el.undo) return;
    var last = state.undo[state.undo.length - 1];
    el.undo.disabled = !last;
    el.undo.title = last ? "Undo: " + last.label + " (Ctrl+Z)" : "Nothing to undo (Ctrl+Z)";
  }

  function pushUndo(entry) {
    state.undo.push(entry);
    if (state.undo.length > UNDO_LIMIT) state.undo.shift();
    updateUndoButton();
  }

  function clearUndo() {
    state.undo = [];
    updateUndoButton();
  }

  /* Reverse the last change to the graph: an add, a removal, a hide or a clear. */
  function undo() {
    var g = state.graph;
    var entry = state.undo.pop();
    updateUndoButton();
    if (!entry || !g) {
      setStatus("Nothing to undo.", "warn");
      return;
    }
    stopLayout();
    if (entry.kind === "add") {
      entry.edges.forEach(function (id) { if (g.hasEdge(id)) g.dropEdge(id); });
      entry.nodes.forEach(function (id) { if (g.hasNode(id)) g.dropNode(id); });
      Object.keys(entry.prev).forEach(function (id) {
        if (g.hasNode(id)) g.setNodeAttribute(id, "data", entry.prev[id]);
      });
    } else if (entry.kind === "remove") {
      g.addNode(entry.id, entry.attrs);
      entry.edges.forEach(function (e) {
        if (g.hasNode(e.source) && g.hasNode(e.target) && !g.hasEdge(e.id)) {
          g.addDirectedEdgeWithKey(e.id, e.source, e.target, e.attrs);
        }
      });
    } else if (entry.kind === "hide") {
      if (g.hasNode(entry.id)) g.setNodeAttribute(entry.id, "userHidden", entry.was);
    } else if (entry.kind === "clear") {
      g.import(entry.data);
      state.layers = entry.layers;
    }
    resizeAll();
    refreshVisibility();
    if (state.selected && !g.hasNode(state.selected)) select(null);
    else renderDetail();
    updateCounts();
    refreshFind();
    setStatus("Undid: " + entry.label + ".", "ok");
  }

  /* A node shows unless its type is filtered, every dataset it came from is
   * switched off, it falls outside the time range, it is shared by too many
   * sites to be a useful link (noise filter), or the analyst hid it by hand. */
  var NOISY_TYPES = { ip: true, asn: true, tls_cert: true, tech: true, third_party: true, ptr: true, cidr: true };

  function siteNeighbours(id) {
    var out = [];
    state.graph.forEachNeighbor(id, function (other, attrs) {
      if (attrs.ntype === "site") out.push(other);
    });
    return out;
  }

  function inTimeRange(data) {
    var t = state.time;
    if (!t.from && !t.to) return true;
    var first = data.first_seen || data.last_seen;
    var last = data.last_seen || data.first_seen;
    if (!first || !last) return true;
    if (t.from && last < t.from) return false;
    if (t.to && first > t.to) return false;
    return true;
  }

  function refreshVisibility() {
    var g = state.graph;
    if (!g) return;
    var timeOn = !!(state.time.from || state.time.to);
    var timeHidden = {};
    if (timeOn) {
      g.forEachNode(function (id, attrs) {
        if (attrs.ntype === "site" && !inTimeRange(attrs.data || {})) timeHidden[id] = true;
      });
    }
    g.updateEachNodeAttributes(function (id, attrs) {
      var layers = (attrs.data && attrs.data.layers) || [];
      var layerShown = !layers.length;
      var i;
      for (i = 0; i < layers.length; i++) {
        if (!state.layers[layers[i]] || !state.layers[layers[i]].hidden) layerShown = true;
      }
      var hidden = !!(attrs.userHidden || state.hiddenTypes[attrs.ntype] || !layerShown);
      if (!hidden && timeOn) {
        if (timeHidden[id]) {
          hidden = true;
        } else if (attrs.ntype !== "site") {
          var sites = siteNeighbours(id);
          if (sites.length && sites.every(function (n) { return timeHidden[n]; })) hidden = true;
        }
      }
      if (!hidden && state.noiseMax !== null && NOISY_TYPES[attrs.ntype] && siteNeighbours(id).length > state.noiseMax) {
        hidden = true;
      }
      attrs.hidden = hidden;
      return attrs;
    });

    /* Declutter: hide sites with fewer than N connections to nodes that are
     * still visible after every other filter (and anything left with no visible
     * neighbour by that). A connection is a distinct
     * visible neighbour, so parallel edges count once. The selected node and
     * the nodes of an active search stay. */
    var dropped = 0;
    if (state.declutter.on) {
      var drop = {};
      g.forEachNode(function (id, attrs) {
        if (attrs.ntype !== "site" || attrs.hidden) return;
        if (id === state.selected || (state.find.active && state.find.set[id])) return;
        var seen = {};
        var count = 0;
        g.forEachNeighbor(id, function (other, otherAttrs) {
          if (!otherAttrs.hidden && !seen[other]) {
            seen[other] = true;
            count += 1;
          }
        });
        if (count < state.declutter.min) {
          drop[id] = true;
          dropped += 1;
        }
      });
      if (dropped) {
        /* A node whose only visible neighbours were the sites just hidden (a
         * site's own domain, say) would be left floating, so it goes too. A
         * node that still touches something else stays. */
        var strand = {};
        g.forEachNode(function (id, attrs) {
          if (attrs.ntype === "site" || attrs.hidden || id === state.selected) return;
          if (state.find.active && state.find.set[id]) return;
          var lost = 0;
          var kept = 0;
          g.forEachNeighbor(id, function (other, otherAttrs) {
            if (otherAttrs.hidden) return;
            if (drop[other]) lost += 1; else kept += 1;
          });
          if (lost && !kept) {
            strand[id] = true;
            dropped += 1;
          }
        });
        g.updateEachNodeAttributes(function (id, attrs) {
          if (drop[id] || strand[id]) attrs.hidden = true;
          return attrs;
        });
      }
    }
    state.declutter.hidden = dropped;
    updateDeclutterLabel();
    refreshFind();
  }

  function updateDeclutterLabel() {
    if (!el.declutter) return;
    var d = state.declutter;
    el.declutter.textContent = d.on ? "Declutter: " + d.hidden + " hidden" : "Declutter";
    el.declutter.setAttribute("aria-pressed", String(d.on));
    el.declutter.classList.toggle("is-on", d.on);
    if (el.declutterN) el.declutterN.value = String(d.min);
  }

  function setDeclutter(on, min) {
    var d = state.declutter;
    d.on = !!on;
    if (typeof min === "number" && min >= 1 && min <= 10) d.min = Math.round(min);
    refreshVisibility();
    /* Sites that came back may never have been laid out while they were hidden. */
    runLayout(NEXT_LAYOUT_ITERATIONS);
    if (state.renderer) state.renderer.refresh();
  }

  /* Public entry for imported datasets (static/js/titaneye-import.js). */
  function addFragment(fragment, layer) {
    var before = state.graph ? state.graph.order : 0;
    var added = merge(fragment, null, layer);
    updateCounts();
    runLayout(before ? NEXT_LAYOUT_ITERATIONS : FIRST_LAYOUT_ITERATIONS);
    setStatus(
      "Imported " + layer + ": " + added.nodes + " new nodes, " + added.edges + " new edges.",
      added.nodes || added.edges ? "ok" : "warn"
    );
    return added;
  }

  /* ------------------------------------------------------------- layout */

  var PPN = 10;   /* floats per node and per edge in the ForceAtlas2 matrices */
  var PPE = 3;
  var LAYOUT_BATCH = 10;
  var LAYOUT_SCALING = 20;
  var LAYOUT_GRAVITY = 0.05;

  function stopLayout() {
    state.layoutToken += 1;
    if (state.worker) {
      state.worker.terminate();
      state.worker = null;
    }
    if (el.layoutNote) el.layoutNote.textContent = "";
  }

  /* ForceAtlas2 runs in a worker so a large graph never freezes the page.
   * The worker gets flat matrices, iterates, and posts positions back every
   * LAYOUT_BATCH iterations. Changing the graph restarts it from the current
   * positions. */
  function layoutSettings(order, override) {
    var settings = window.ForceAtlas2.inferSettings(order);
    settings.barnesHutOptimize = order > 400;
    settings.slowDown = 1 + Math.log(order);
    settings.linLogMode = order > 300;
    settings.scalingRatio = LAYOUT_SCALING;
    settings.gravity = LAYOUT_GRAVITY;
    var key;
    for (key in override) if (Object.prototype.hasOwnProperty.call(override, key)) settings[key] = override[key];
    return settings;
  }

  /* Lays out the nodes that are on screen. Hidden nodes keep their positions.
   * By default only nodes that have never been laid out move; the rest are
   * held in place so expanding a node does not rearrange the graph. Pass
   * {full: true} (the Tidy button) to move everything. */
  function runLayout(iterations, options) {
    options = options || {};
    var g = state.graph;
    var done = function () { if (options.onDone) options.onDone(); };
    if (!g || !window.Worker || !window.ForceAtlas2) { done(); return; }

    var ids = [];
    var fresh = 0;
    g.forEachNode(function (id, attrs) {
      if (attrs.hidden) return;
      ids.push(id);
      if (!attrs.placed) fresh += 1;
    });
    if (ids.length < 2 || (!options.full && !fresh)) {
      g.updateEachNodeAttributes(function (id, attrs) { if (!attrs.hidden) attrs.placed = true; return attrs; });
      done();
      return;
    }
    stopLayout();
    var token = state.layoutToken;

    var offset = {};
    var degree = {};
    ids.forEach(function (id, i) {
      offset[id] = i * PPN;
      degree[id] = 0;
    });
    var pairs = [];
    g.forEachEdge(function (edge, attrs, source, target) {
      if (offset[source] === undefined || offset[target] === undefined) return;
      pairs.push(offset[source], offset[target]);
      degree[source] += 1;
      degree[target] += 1;
    });
    var holdExisting = !options.full && fresh < ids.length;
    var nodes = new Float32Array(ids.length * PPN);
    ids.forEach(function (id) {
      var at = offset[id];
      var attrs = g.getNodeAttributes(id);
      nodes[at] = attrs.x;
      nodes[at + 1] = attrs.y;
      nodes[at + 6] = 1 + degree[id];
      nodes[at + 7] = 1;
      nodes[at + 8] = 1;
      nodes[at + 9] = holdExisting && attrs.placed ? 1 : 0;
    });
    var edges = new Float32Array((pairs.length / 2) * PPE);
    var k;
    for (k = 0; k < pairs.length / 2; k++) {
      edges[k * PPE] = pairs[k * 2];
      edges[k * PPE + 1] = pairs[k * 2 + 1];
      edges[k * PPE + 2] = 1;
    }
    g.updateEachNodeAttributes(function (id, attrs) {
      if (offset[id] !== undefined) attrs.placed = true;
      return attrs;
    });

    var settings = layoutSettings(ids.length, options.settings || {});
    var worker;
    try {
      worker = new window.Worker(el.root.getAttribute("data-worker"));
    } catch (err) {
      el.layoutNote.textContent = "Layout unavailable";
      done();
      return;
    }
    state.worker = worker;
    el.layoutNote.textContent = "Laying out…";

    worker.onmessage = function (event) {
      if (token !== state.layoutToken || !state.graph) return;
      var out = new Float32Array(event.data.nodes);
      g.updateEachNodeAttributes(function (id, attrs) {
        var at = offset[id];
        if (at !== undefined) {
          attrs.x = out[at];
          attrs.y = out[at + 1];
        }
        return attrs;
      });
      if (event.data.finished) {
        stopLayout();
        done();
      }
    };
    worker.onerror = function () {
      if (token === state.layoutToken) {
        stopLayout();
        el.layoutNote.textContent = "Layout stopped";
      }
    };
    worker.postMessage(
      { nodes: nodes.buffer, edges: edges.buffer, settings: settings,
        iterations: iterations, batch: LAYOUT_BATCH },
      [nodes.buffer, edges.buffer]
    );
  }

  /* ---------------------------------------------------------- selection */

  function select(node) {
    var g = state.graph;
    state.selected = node && g && g.hasNode(node) ? node : null;
    state.neighbors = {};
    if (state.selected) {
      g.forEachNeighbor(state.selected, function (other) { state.neighbors[other] = true; });
    }
    renderDetail();
    /* The right-hand panel shows the scale view until a node is selected, then that node's details. */
    el.detail.hidden = !state.selected;
    state.selectListeners.forEach(function (listener) { listener(state.selected); });
    if (state.renderer) state.renderer.refresh();
  }

  /* --------------------------------------------------------------- find */

  var FIND_DELAY = 120;
  var FIND_LIST_MAX = 40;

  function typeFromToken(token) {
    token = token.toLowerCase().replace(/[\s-]+/g, "_");
    var found = null;
    Object.keys(TYPES).forEach(function (type) {
      if (type === token || TYPES[type].label.toLowerCase().replace(/\s+/g, "_") === token) found = type;
    });
    return found;
  }

  /* Everything a node can be found by: its value, id, type name and every
   * scalar or list attribute (scan IDs, countries, chains, URLs...). */
  function searchText(id, attrs) {
    var parts = [attrs.full || "", id, TYPES[attrs.ntype].label];
    var data = attrs.data || {};
    Object.keys(data).forEach(function (key) {
      var value = data[key];
      if (Array.isArray(value)) parts.push(value.join(" "));
      else if (value !== null && typeof value !== "object") parts.push(String(value));
    });
    return parts.join("\n").toLowerCase();
  }

  /* "type:ip 203.0" limits the search to one node type. */
  function parseFind(text) {
    var match = /^\s*type:(\S+)\s*(.*)$/i.exec(text);
    if (match) {
      var type = typeFromToken(match[1]);
      if (type) return { type: type, needle: match[2].trim().toLowerCase() };
    }
    return { type: null, needle: text.trim().toLowerCase() };
  }

  function runFind(keepCurrent) {
    var f = state.find;
    var query = parseFind(el.findInput.value);
    var g = state.graph;
    var previous = f.current;
    f.matches = [];
    f.set = {};
    f.active = !!(g && (query.needle || query.type));
    if (f.active) {
      g.forEachNode(function (id, attrs) {
        if (attrs.hidden) return;
        if (query.type && attrs.ntype !== query.type) return;
        if (query.needle && searchText(id, attrs).indexOf(query.needle) === -1) return;
        f.matches.push(id);
        f.set[id] = true;
      });
      f.matches.sort(function (a, b) {
        return g.degree(b) - g.degree(a);
      });
    }
    f.index = keepCurrent && previous && f.set[previous] ? f.matches.indexOf(previous) : (f.matches.length ? 0 : -1);
    f.current = f.index >= 0 ? f.matches[f.index] : null;
    renderFindResults();
    if (state.renderer) state.renderer.refresh();
    if (f.current && !keepCurrent) focusNode(f.current);
  }

  function focusNode(id) {
    if (!state.renderer) return;
    var shown = state.renderer.getNodeDisplayData(id);
    if (!shown) return;
    var camera = state.renderer.getCamera();
    camera.animate({ x: shown.x, y: shown.y, ratio: Math.min(camera.ratio, 0.35) }, { duration: 300 });
  }

  function stepFind(direction) {
    var f = state.find;
    if (!f.matches.length) return;
    f.index = (f.index + direction + f.matches.length) % f.matches.length;
    f.current = f.matches[f.index];
    renderFindResults();
    focusNode(f.current);
    if (state.renderer) state.renderer.refresh();
  }

  function pickFindResult(id) {
    var f = state.find;
    f.index = f.matches.indexOf(id);
    f.current = id;
    select(id);
    focusNode(id);
    renderFindResults();
  }

  function renderFindResults() {
    var f = state.find;
    var g = state.graph;
    clearChildren(el.findList);
    if (!f.active) {
      el.findCount.textContent = "";
      return;
    }
    el.findCount.textContent = f.matches.length
      ? (f.index + 1) + " of " + f.matches.length
      : "No matches";
    f.matches.slice(0, FIND_LIST_MAX).forEach(function (id) {
      var item = make("li");
      var button = make("button", "te-find__item");
      button.type = "button";
      if (id === f.current) button.setAttribute("aria-current", "true");
      var dot = make("span", "te-legend__swatch");
      dot.style.background = TYPES[g.getNodeAttribute(id, "ntype")].color;
      button.appendChild(dot);
      button.appendChild(make("span", "te-find__label", clip(g.getNodeAttribute(id, "full"), 48)));
      button.appendChild(make("span", "te-find__type", TYPES[g.getNodeAttribute(id, "ntype")].label));
      button.addEventListener("click", function () { pickFindResult(id); });
      item.appendChild(button);
      el.findList.appendChild(item);
    });
    if (f.matches.length > FIND_LIST_MAX) {
      el.findList.appendChild(make("li", "te-find__more", "+ " + (f.matches.length - FIND_LIST_MAX) + " more. Step through them with Enter."));
    }
  }

  function clearChildren(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function openFind() {
    el.find.hidden = false;
    el.findInput.focus();
    el.findInput.select();
    if (el.findInput.value) runFind(true);
  }

  function closeFind() {
    el.find.hidden = true;
    state.find.active = false;
    state.find.matches = [];
    state.find.set = {};
    state.find.current = null;
    clearChildren(el.findList);
    el.findCount.textContent = "";
    if (state.renderer) state.renderer.refresh();
  }

  /* Keep an open search in step with a graph that just changed. */
  function refreshFind() {
    if (!el.find.hidden && el.findInput.value) runFind(true);
  }

  function copyButton(text, label) {
    var button = make("button", "btn btn--ghost btn--small", label || "Copy");
    button.type = "button";
    button.addEventListener("click", function () {
      try {
        navigator.clipboard.writeText(text).then(function () {
          button.textContent = "Copied";
          window.setTimeout(function () { button.textContent = label || "Copy"; }, 1200);
        }, function () { button.textContent = "Copy failed"; });
      } catch (err) {
        button.textContent = "Copy failed";
      }
    });
    return button;
  }

  function row(name, value) {
    var wrap = make("div", "te-fact");
    wrap.appendChild(make("dt", null, name));
    wrap.appendChild(make("dd", null, value));
    return wrap;
  }

  function nodeValue(id) {
    return id.slice(id.indexOf(":") + 1);
  }

  function detailTransforms(type, value, anchor) {
    var list = state.transforms.filter(function (t) { return t.node_type === type; });
    if (!list.length) return null;
    var box = make("div", "te-section");
    box.appendChild(make("h3", "te-section__title", "Expand"));
    list.forEach(function (t) {
      var item = make("div", "te-transform");
      var button = make("button", "btn btn--small" + (t.plan === "pro" ? " te-pro" : ""), t.label);
      button.type = "button";
      button.addEventListener("click", function () { expand(t.id, value, anchor); });
      item.appendChild(button);
      if (t.plan === "pro") item.appendChild(make("span", "te-badge", "Pro"));
      item.appendChild(make("code", "te-transform__query", t.template.replace("{v}", clip(value, 60))));
      box.appendChild(item);
    });
    return box;
  }

  function renderDetail() {
    var root = el.detail;
    while (root.firstChild) root.removeChild(root.firstChild);
    var g = state.graph;
    if (!state.selected || !g) return;
    var id = state.selected;
    var type = g.getNodeAttribute(id, "ntype");
    var data = g.getNodeAttribute(id, "data") || {};
    var value = nodeValue(id);

    var head = make("div", "te-detail__head");
    var overview = make("button", "btn btn--ghost btn--small te-detail__back", "← Scale view");
    overview.type = "button";
    overview.addEventListener("click", function () { select(null); });
    head.appendChild(overview);
    var chip = make("span", "te-chip", TYPES[type].label);
    chip.style.borderColor = TYPES[type].color;
    chip.style.color = TYPES[type].color;
    head.appendChild(chip);
    root.appendChild(head);

    var valueLine = make("div", "te-value");
    valueLine.appendChild(make("code", "te-value__text", value));
    valueLine.appendChild(copyButton(value));
    root.appendChild(valueLine);

    var facts = make("dl", "te-facts");
    facts.appendChild(row("Connections", String(g.degree(id))));
    var counts = {};
    g.forEachNeighbor(id, function (other) {
      var t = g.getNodeAttribute(other, "ntype");
      counts[t] = (counts[t] || 0) + 1;
    });
    Object.keys(counts).sort().forEach(function (t) {
      facts.appendChild(row(TYPES[t].label + "s linked", String(counts[t])));
    });
    if (Array.isArray(data.chains) && data.chains.length) facts.appendChild(row("chains", data.chains.join(", ")));
    if (Array.isArray(data.layers) && data.layers.length) facts.appendChild(row("from", data.layers.join(", ")));
    ["first_seen", "last_seen", "country", "status", "domain_age_days", "name"].forEach(function (k) {
      if (data[k] !== undefined && data[k] !== null) facts.appendChild(row(k.replace(/_/g, " "), String(data[k])));
    });
    if (data.scanned_url) {
      var urlRow = make("div", "te-fact");
      urlRow.appendChild(make("dt", null, "scanned url"));
      var urlCell = make("dd", "te-fact__url");
      urlCell.appendChild(make("code", null, clip(data.scanned_url, 120)));
      urlCell.appendChild(copyButton(data.scanned_url));
      urlRow.appendChild(urlCell);
      facts.appendChild(urlRow);
    }
    root.appendChild(facts);

    if (type === "site") {
      if (typeof data.screenshot === "string" && data.screenshot.indexOf("https://urlscan.io/") === 0) {
        var shot = make("img", "te-shot");
        shot.alt = "Screenshot of " + value;
        shot.loading = "lazy";
        shot.referrerPolicy = "no-referrer";
        shot.src = data.screenshot;
        root.appendChild(shot);
      }
      var actions = make("div", "te-section");
      actions.appendChild(make("h3", "te-section__title", "Investigate"));
      (data.scans || []).forEach(function (uuid) {
        var line = make("div", "te-transform");
        var open = make("button", "btn btn--small", "Open scan in analyzer");
        open.type = "button";
        open.addEventListener("click", function () {
          if (opts.onAnalyze) opts.onAnalyze(uuid);
        });
        line.appendChild(open);
        line.appendChild(make("code", "te-transform__query", uuid));
        line.appendChild(copyButton(uuid));
        actions.appendChild(line);
      });
      var grid = make("button", "btn btn--ghost btn--small", "Search this domain in the grid");
      grid.type = "button";
      grid.addEventListener("click", function () {
        if (opts.onSearch) opts.onSearch("page.domain:" + value);
      });
      actions.appendChild(grid);
      root.appendChild(actions);
    }

    state.detailSections.forEach(function (build) {
      var section = build({ id: id, type: type, value: value, data: data });
      if (section) root.appendChild(section);
    });

    var transforms = detailTransforms(type, value, id);
    if (transforms) root.appendChild(transforms);

    var tools = make("div", "te-section");
    var hide = make("button", "btn btn--ghost btn--small", "Hide node");
    hide.type = "button";
    hide.addEventListener("click", function () {
      pushUndo({ kind: "hide", id: id, was: !!g.getNodeAttribute(id, "userHidden"), label: "hide " + clip(value, 40) });
      g.setNodeAttribute(id, "userHidden", true);
      refreshVisibility();
      select(null);
    });
    var remove = make("button", "btn btn--ghost btn--small", "Remove from graph");
    remove.type = "button";
    remove.addEventListener("click", function () { removeNode(id); });
    tools.appendChild(hide);
    tools.appendChild(remove);
    root.appendChild(tools);
  }

  /* Take a node and its edges off the graph; Undo puts them back. */
  function removeNode(id) {
    var g = state.graph;
    if (!g || !g.hasNode(id)) return;
    stopLayout();
    var removed = { kind: "remove", id: id, attrs: g.getNodeAttributes(id), edges: [],
                    label: "remove " + clip(nodeValue(id), 40) };
    g.forEachEdge(id, function (edge, attrs, source, target) {
      removed.edges.push({ id: edge, source: source, target: target, attrs: attrs });
    });
    pushUndo(removed);
    g.dropNode(id);
    resizeAll();
    select(null);
    updateCounts();
    refreshFind();
    setStatus("Removed " + clip(removed.label.slice(7), 60) + ". Ctrl+Z puts it back.", "ok");
  }

  /* ------------------------------------------------------------- legend */

  function updateCounts() {
    var counts = {};
    var g = state.graph;
    if (g) {
      g.forEachNode(function (node, attrs) {
        counts[attrs.ntype] = (counts[attrs.ntype] || 0) + 1;
      });
    }
    Object.keys(TYPES).forEach(function (type) {
      var button = el.legendButtons[type];
      button.querySelector(".te-legend__count").textContent = String(counts[type] || 0);
      button.hidden = !counts[type];
    });
    renderLayers();
    applyLabelSettings();
    state.listeners.forEach(function (listener) { listener(); });
    el.summary.textContent = g
      ? g.order + " nodes · " + g.size + " edges"
      : "0 nodes · 0 edges";
  }

  /* One toggle per data source: "urlscan" for expansions, "file:<name>" per import. */
  function renderLayers() {
    var names = Object.keys(state.layers);
    var counts = {};
    if (state.graph) {
      state.graph.forEachNode(function (node, attrs) {
        ((attrs.data && attrs.data.layers) || []).forEach(function (layer) {
          counts[layer] = (counts[layer] || 0) + 1;
        });
      });
    }
    while (el.layers.firstChild) el.layers.removeChild(el.layers.firstChild);
    el.layers.hidden = names.length < 2;
    names.forEach(function (name) {
      var button = make("button", "te-legend__item");
      button.type = "button";
      button.setAttribute("aria-pressed", String(!state.layers[name].hidden));
      button.title = "Show or hide everything that came only from " + name;
      button.appendChild(make("span", null, clip(name, 40)));
      button.appendChild(make("span", "te-legend__count", String(counts[name] || 0)));
      button.addEventListener("click", function () {
        state.layers[name].hidden = !state.layers[name].hidden;
        button.setAttribute("aria-pressed", String(!state.layers[name].hidden));
        refreshVisibility();
      });
      el.layers.appendChild(button);
    });
  }

  function buildLegend() {
    el.legendButtons = {};
    Object.keys(TYPES).forEach(function (type) {
      var button = make("button", "te-legend__item");
      button.type = "button";
      button.setAttribute("aria-pressed", "true");
      var swatch = make("span", "te-legend__swatch");
      swatch.style.background = TYPES[type].color;
      button.appendChild(swatch);
      button.appendChild(make("span", null, TYPES[type].label));
      button.appendChild(make("span", "te-legend__count", "0"));
      button.hidden = true;
      button.addEventListener("click", function () {
        var hide = !state.hiddenTypes[type];
        state.hiddenTypes[type] = hide;
        button.setAttribute("aria-pressed", String(!hide));
        refreshVisibility();
      });
      el.legend.appendChild(button);
      el.legendButtons[type] = button;
    });
  }

  /* ---------------------------------------------------------- expansion */

  function expand(transform, value, anchor, cursor) {
    if (state.busy) return;
    if (!value) {
      setStatus("Enter a value first.", "warn");
      return;
    }
    var size = parseInt(el.size.value, 10) || 100;
    var body = { transform: transform, value: value, size: size };
    if (cursor) body.search_after = cursor;
    setBusy(true);
    setStatus("Querying urlscan.io…");
    api("POST", "/api/graph/expand", body).then(function (data) {
      var before = state.graph ? state.graph.order : 0;
      var added = merge(data, anchor, "urlscan");
      var meta = data.meta || {};
      var cursorKey = transform + "|" + value;
      if (meta.has_more && meta.next_cursor) {
        state.cursors[cursorKey] = {
          transform: transform, value: value, cursor: meta.next_cursor, anchor: anchor
        };
      } else {
        delete state.cursors[cursorKey];
      }
      state.lastKey = meta.has_more ? cursorKey : null;
      el.more.hidden = !meta.has_more;
      var total = typeof meta.total === "number"
        ? " of " + (meta.total_is_exact ? "" : "at least ") + meta.total
        : "";
      setStatus(
        "Got " + meta.count + total + " scans for " + clip(meta.query, 90) + ". " +
        added.nodes + " new nodes, " + added.edges + " new edges." +
        (meta.has_more ? " More results are available." : ""),
        added.nodes || added.edges ? "ok" : "warn"
      );
      updateCounts();
      runLayout(before ? NEXT_LAYOUT_ITERATIONS : FIRST_LAYOUT_ITERATIONS);
      if (meta.seed && state.graph.hasNode(meta.seed)) select(meta.seed);
    }).catch(function (err) {
      setStatus(err.message, "error");
    }).then(function () {
      setBusy(false);
    });
  }

  function loadMore() {
    var pending = state.lastKey && state.cursors[state.lastKey];
    if (!pending) return;
    expand(pending.transform, pending.value, pending.anchor, pending.cursor);
  }

  function runFromToolbar() {
    var transform = el.transform.value;
    var value = (el.value.value || "").trim();
    expand(transform, value, null);
  }

  /* ----------------------------------------------------------- lifecycle */

  function fillTransformSelect() {
    var query = make("option", null, "Free-form urlscan query");
    query.value = "query";
    el.transform.appendChild(query);
    state.transforms.forEach(function (t) {
      var option = make("option", null, TYPES[t.node_type].label + ": " + t.label + (t.plan === "pro" ? " (Pro)" : ""));
      option.value = t.id;
      el.transform.appendChild(option);
    });
  }

  function loadTransforms() {
    if (state.transforms.length) return;
    api("GET", "/api/graph/transforms").then(function (data) {
      state.transforms = data.transforms || [];
      fillTransformSelect();
    }).catch(function (err) {
      setStatus("Could not load the transform list: " + err.message, "error");
    });
  }

  function open() {
    if (!state.ready) return;
    el.root.hidden = false;
    document.body.classList.add("te-open");
    loadTransforms();
    ensureGraph();
    state.renderer.resize();
    state.renderer.refresh();
    el.value.focus();
  }

  function close() {
    if (!state.ready) return;
    el.root.hidden = true;
    document.body.classList.remove("te-open");
    stopLayout();
    if (opts.onClose) opts.onClose();
  }

  function clearGraph() {
    if (!state.graph || !state.graph.order) return;
    if (!window.confirm("Remove every node and edge from the graph?")) return;
    stopLayout();
    pushUndo({ kind: "clear", data: state.graph.export(), layers: state.layers,
               label: "clear " + state.graph.order + " nodes" });
    state.graph.clear();
    state.cursors = {};
    state.layers = {};
    state.lastKey = null;
    el.more.hidden = true;
    select(null);
    updateCounts();
    refreshFind();
    setStatus("Graph cleared.");
  }

  function init(options) {
    opts = options || {};
    el.root = $("titaneye");
    if (!el.root || !window.graphology || !window.Sigma) return;
    el.canvas = $("te-canvas");
    el.detail = $("te-detail");
    el.legend = $("te-legend");
    el.layers = $("te-layers");
    el.status = $("te-status");
    el.summary = $("te-summary");
    el.layoutNote = $("te-layout-note");
    el.transform = $("te-transform");
    el.value = $("te-value");
    el.size = $("te-size");
    el.run = $("te-run");
    el.more = $("te-more");
    el.clear = $("te-clear");
    el.undo = $("te-undo");
    el.back = $("te-back");
    el.tip = $("te-tip");
    el.tipValue = $("te-tip-value");
    el.tipMeta = $("te-tip-meta");
    el.declutter = $("te-declutter");
    el.declutterN = $("te-declutter-n");
    el.edges = $("te-edges");
    el.find = $("te-find");
    el.findInput = $("te-find-input");
    el.findCount = $("te-find-count");
    el.findList = $("te-find-list");

    buildLegend();
    renderDetail();
    updateCounts();

    el.run.addEventListener("click", runFromToolbar);
    el.value.addEventListener("keydown", function (event) {
      if (event.key === "Enter") runFromToolbar();
    });
    el.more.addEventListener("click", loadMore);
    el.clear.addEventListener("click", clearGraph);
    el.undo.addEventListener("click", undo);
    updateUndoButton();
    el.back.addEventListener("click", close);
    el.declutter.addEventListener("click", function () { setDeclutter(!state.declutter.on); });
    el.declutterN.addEventListener("change", function () {
      var n = parseInt(el.declutterN.value, 10);
      setDeclutter(state.declutter.on, n >= 1 && n <= 10 ? n : state.declutter.min);
      updateDeclutterLabel();
    });
    el.edges.addEventListener("change", function () {
      state.edgeMode = el.edges.value;
      if (state.renderer) state.renderer.refresh();
    });
    updateDeclutterLabel();
    $("te-find-open").addEventListener("click", openFind);
    $("te-find-close").addEventListener("click", closeFind);
    $("te-find-prev").addEventListener("click", function () { stepFind(-1); });
    $("te-find-next").addEventListener("click", function () { stepFind(1); });
    var findTimer = null;
    var findPending = false;
    el.findInput.addEventListener("input", function () {
      window.clearTimeout(findTimer);
      findPending = true;
      findTimer = window.setTimeout(function () {
        findPending = false;
        runFind(false);
      }, FIND_DELAY);
    });
    el.findInput.addEventListener("keydown", function (event) {
      if (event.key === "Enter") {
        event.preventDefault();
        if (findPending) {
          /* Enter before the debounce fired: search now and land on the first match. */
          window.clearTimeout(findTimer);
          findPending = false;
          runFind(false);
        } else {
          stepFind(event.shiftKey ? -1 : 1);
        }
      }
    });
    document.addEventListener("keydown", function (event) {
      if (el.root.hidden) return;
      /* The analyzer opens over the graph and the grid is a separate page: leave the browser's own
       * find and undo alone there, and while any dialog is open. */
      if (window.URLScanAnalyzer && window.URLScanAnalyzer.isOpen()) return;
      if (document.querySelector(".te-modal:not([hidden])")) return;
      var typing = /^(input|textarea|select)$/i.test((event.target && event.target.tagName) || "") ||
        !!(event.target && event.target.isContentEditable);
      var shortcut = (event.ctrlKey || event.metaKey) && !event.altKey;
      var letter = (event.key || "").toLowerCase();
      if (shortcut && letter === "f") {
        /* Take Ctrl+F from the browser only while the graph is on screen. */
        event.preventDefault();
        openFind();
      } else if (!shortcut && !event.altKey && (event.key === "Backspace" || event.key === "Delete")) {
        /* Backspace or Delete removes the selected node (not while typing in a box). */
        if (typing || !state.selected) return;
        event.preventDefault();
        removeNode(state.selected);
      } else if (shortcut && !event.shiftKey && letter === "z") {
        /* In a text box Ctrl+Z undoes typing, not the graph. */
        if (typing) return;
        event.preventDefault();
        undo();
      } else if (event.key === "Escape") {
        if (!el.find.hidden) closeFind();
        else close();
      }
    });
    window.addEventListener("resize", function () {
      if (state.renderer && !el.root.hidden) state.renderer.resize();
    });
    state.ready = true;
  }

  /* ------------------------------------------------- hooks for the add-ons */

  function snapshot() {
    var g = state.graph;
    var out = { nodes: [], edges: [], layers: {}, hiddenTypes: {},
                declutter: { on: state.declutter.on, min: state.declutter.min } };
    if (!g) return out;
    g.forEachNode(function (id, attrs) {
      out.nodes.push({ id: id, type: attrs.ntype, label: attrs.full, attrs: attrs.data || {},
                       x: attrs.x, y: attrs.y, hidden: !!attrs.userHidden });
    });
    g.forEachEdge(function (id, attrs, source, target) {
      out.edges.push({ id: id, source: source, target: target, type: attrs.etype, attrs: attrs.data || {} });
    });
    Object.keys(state.layers).forEach(function (name) { out.layers[name] = { hidden: !!state.layers[name].hidden }; });
    Object.keys(state.hiddenTypes).forEach(function (type) { if (state.hiddenTypes[type]) out.hiddenTypes[type] = true; });
    return out;
  }

  /* Replace the graph with a saved snapshot, keeping its saved positions. */
  function loadSnapshot(snap) {
    ensureGraph();
    stopLayout();
    clearUndo();
    state.graph.clear();
    state.layers = {};
    state.cursors = {};
    state.lastKey = null;
    el.more.hidden = true;
    var g = state.graph;
    (snap.nodes || []).forEach(function (n) {
      if (!TYPES[n.type] || typeof n.id !== "string" || g.hasNode(n.id)) return;
      g.addNode(n.id, {
        label: clip(String(n.label), MAX_LABEL), full: String(n.label), ntype: n.type,
        color: TYPES[n.type].color, size: 3,
        x: typeof n.x === "number" ? n.x : 0, y: typeof n.y === "number" ? n.y : 0,
        hidden: false, placed: true, userHidden: !!n.hidden, data: n.attrs && typeof n.attrs === "object" ? n.attrs : {}
      });
    });
    (snap.edges || []).forEach(function (e) {
      if (!g.hasNode(e.source) || !g.hasNode(e.target) || g.hasEdge(e.id)) return;
      g.addDirectedEdgeWithKey(e.id, e.source, e.target, {
        etype: e.type, size: 1, color: EDGE_COLOR, data: e.attrs && typeof e.attrs === "object" ? e.attrs : {}
      });
    });
    Object.keys(snap.layers || {}).forEach(function (name) {
      state.layers[name] = { hidden: !!snap.layers[name].hidden };
    });
    state.hiddenTypes = {};
    Object.keys(snap.hiddenTypes || {}).forEach(function (type) { state.hiddenTypes[type] = true; });
    Object.keys(el.legendButtons).forEach(function (type) {
      el.legendButtons[type].setAttribute("aria-pressed", String(!state.hiddenTypes[type]));
    });
    var saved = snap.declutter || {};
    state.declutter.on = saved.on === true;
    state.declutter.min = typeof saved.min === "number" && saved.min >= 1 && saved.min <= 10 ? Math.round(saved.min) : 2;
    resizeAll();
    refreshVisibility();
    select(null);
    updateCounts();
    state.renderer.refresh();
    return { nodes: g.order, edges: g.size };
  }

  function setNodeData(id, key, value) {
    var g = state.graph;
    if (!g || !g.hasNode(id)) return;
    var data = g.getNodeAttribute(id, "data") || {};
    data[key] = value;
    g.setNodeAttribute(id, "data", data);
    if (state.selected === id) renderDetail();
  }

  /* Dim everything outside ids (used by clusters). The find box owns the
   * same highlight state, so a highlight is ignored while the box is open. */
  function highlight(ids, current) {
    if (!el.find.hidden) return;
    var f = state.find;
    f.active = true;
    f.matches = ids.slice();
    f.set = {};
    ids.forEach(function (id) { f.set[id] = true; });
    f.index = -1;
    f.current = current || null;
    if (state.renderer) state.renderer.refresh();
  }

  function clearHighlight() {
    if (!el.find.hidden) return;
    var f = state.find;
    f.active = false;
    f.matches = [];
    f.set = {};
    f.current = null;
    if (state.renderer) state.renderer.refresh();
  }

  var core = {
    TYPES: TYPES,
    graph: function () { return state.graph; },
    api: api,
    merge: merge,
    select: select,
    selected: function () { return state.selected; },
    focusNode: focusNode,
    setStatus: setStatus,
    transforms: function () { return state.transforms; },
    layers: function () { return state.layers; },
    runLayout: function (n, options) { runLayout(n || NEXT_LAYOUT_ITERATIONS, options); },
    setPositions: function (positions) {
      if (!state.graph) return;
      state.graph.updateEachNodeAttributes(function (id, attrs) {
        var spot = positions[id];
        if (spot) {
          attrs.x = spot.x;
          attrs.y = spot.y;
          attrs.placed = true;
        }
        return attrs;
      });
    },
    fitCamera: function () {
      if (state.renderer) state.renderer.getCamera().animatedReset({ duration: 300 });
    },
    viewport: function () { return { width: el.canvas.clientWidth, height: el.canvas.clientHeight }; },
    setDeclutter: setDeclutter,
    getDeclutter: function () { return { on: state.declutter.on, min: state.declutter.min, hidden: state.declutter.hidden }; },
    setEdgeMode: function (mode) {
      state.edgeMode = ["auto", "all", "selection", "none"].indexOf(mode) !== -1 ? mode : "auto";
      if (state.renderer) state.renderer.refresh();
    },
    renderer: function () { return state.renderer; },
    stopLayout: stopLayout,
    refreshVisibility: refreshVisibility,
    updateCounts: updateCounts,
    siteNeighbours: siteNeighbours,
    setNodeData: setNodeData,
    snapshot: snapshot,
    loadSnapshot: loadSnapshot,
    highlight: highlight,
    clearHighlight: clearHighlight,
    setTimeRange: function (from, to) {
      state.time.from = from || null;
      state.time.to = to || null;
      refreshVisibility();
    },
    setNoiseMax: function (max) {
      state.noiseMax = typeof max === "number" ? max : null;
      refreshVisibility();
    },
    addDetailSection: function (build) { state.detailSections.push(build); },
    onChange: function (listener) { state.listeners.push(listener); },
    onSelect: function (listener) { state.selectListeners.push(listener); },
    rerenderDetail: function () { renderDetail(); },
    isBusy: function () { return state.busy; }
  };

  return {
    core: core,
    init: init,
    open: open,
    close: close,
    addFragment: addFragment,
    find: function () { if (state.ready && !el.root.hidden) openFind(); },
    uniqueLayerName: function (base) {
      var name = base;
      var n = 2;
      while (state.layers[name]) { name = base + " (" + n + ")"; n += 1; }
      return name;
    },
    isOpen: function () { return state.ready && !el.root.hidden; }
  };
})();
