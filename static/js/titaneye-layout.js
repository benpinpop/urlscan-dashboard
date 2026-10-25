/* TitanEye tidy layouts.
 *
 * The Tidy button re-lays out the nodes that are on screen with the chosen
 * preset. Hidden nodes keep their positions, so they come back somewhere
 * sensible when they are revealed.
 *
 *   Organic    force-directed (ForceAtlas2 in the worker), then leaves of a hub are
 *              fanned out around it, overlapping dots are nudged apart, and
 *              disconnected pieces are packed into a tidy grid.
 *   Rings      concentric rings by kind: evidence in the middle, hosting next, then
 *              domains, then sites on the outside, ordered to keep lines short.
 *   Hierarchy  rows: ASN, then IP, then site, then domain, then the rest.
 *
 * Positions are in graph units; sigma fits the view to them, so spacing here
 * is relative and node radii are converted using the current view size.
 */
window.TitanEyeLayout = (function () {
  "use strict";

  /* Ring (inner to outer) and hierarchy row for each node type. */
  var RING_OF = { wallet: 0, contact: 0, file_hash: 0, filename: 0, text_string: 0, tag: 0, brand: 0, "case": 0,
                  asn: 1, ip: 1, cidr: 1, ptr: 1, tls_cert: 1, tech: 1, third_party: 1,
                  apex_domain: 2, site: 3 };
  var ROW_OF = { asn: 0, ip: 1, cidr: 1, ptr: 1, site: 2, apex_domain: 3 };
  var ROW_DEFAULT = 4;
  var FAN_MIN_LEAVES = 6;
  var RELAX_PASSES = 25;
  var TIDY_ROUNDS = 5;        /* alternate relax and pack until they settle */
  var RELAX_GAP = 1.25;       /* centre distance as a multiple of the two radii */
  var PACK_GAP = 3;           /* gap between packed pieces, in node radii */
  var HIERARCHY_LINE = 70;    /* nodes per line before a row wraps */

  var core = null;
  var el = {};
  var busy = false;
  var stats = { layoutMs: 0, postMs: 0 };

  /* ------------------------------------------------------------- helpers */

  function visibleIds(g) {
    var ids = [];
    g.forEachNode(function (id, attrs) { if (!attrs.hidden) ids.push(id); });
    return ids;
  }

  /* Distinct visible neighbours of each visible node. */
  function adjacency(g, ids) {
    var shown = {};
    ids.forEach(function (id) { shown[id] = true; });
    var adj = {};
    ids.forEach(function (id) {
      var seen = {};
      var list = [];
      g.forEachNeighbor(id, function (other) {
        if (shown[other] && other !== id && !seen[other]) {
          seen[other] = true;
          list.push(other);
        }
      });
      adj[id] = list;
    });
    return adj;
  }

  function extent(pos, ids) {
    var minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    ids.forEach(function (id) {
      var p = pos[id];
      if (p.x < minX) minX = p.x;
      if (p.x > maxX) maxX = p.x;
      if (p.y < minY) minY = p.y;
      if (p.y > maxY) maxY = p.y;
    });
    return { minX: minX, maxX: maxX, minY: minY, maxY: maxY, w: maxX - minX, h: maxY - minY };
  }

  /* Graph units per screen pixel once sigma has fitted the layout to the view. */
  function unitsPerPixel(pos, ids) {
    var box = extent(pos, ids);
    var view = core.viewport();
    var side = Math.max(1, Math.min(view.width, view.height) * 0.8);
    return Math.max(box.w, box.h, 1e-6) / side;
  }

  function radiusOf(g, id, upp) {
    return Math.max(1, g.getNodeAttribute(id, "size")) * upp;
  }

  function positionsOf(g, ids) {
    var pos = {};
    ids.forEach(function (id) {
      pos[id] = { x: g.getNodeAttribute(id, "x"), y: g.getNodeAttribute(id, "y") };
    });
    return pos;
  }

  /* ------------------------------------------------------- organic helpers */

  /* Leaves (one visible connection) of a busy hub go on a ring around it. */
  function fanOut(g, ids, adj, pos, upp) {
    var claimed = {};
    var hubs = ids.filter(function (id) { return adj[id].length >= FAN_MIN_LEAVES; });
    hubs.sort(function (a, b) { return adj[b].length - adj[a].length; });
    hubs.forEach(function (hub) {
      var leaves = adj[hub].filter(function (n) { return adj[n].length === 1 && !claimed[n]; });
      if (leaves.length < FAN_MIN_LEAVES) return;
      var step = 0;
      leaves.forEach(function (n) {
        claimed[n] = true;
        step = Math.max(step, radiusOf(g, n, upp) * 2 * 1.5);
      });
      var radius = Math.max((step * leaves.length) / (2 * Math.PI), radiusOf(g, hub, upp) + step);
      leaves.forEach(function (n, i) {
        var angle = (2 * Math.PI * i) / leaves.length;
        pos[n].x = pos[hub].x + Math.cos(angle) * radius;
        pos[n].y = pos[hub].y + Math.sin(angle) * radius;
      });
    });
  }

  /* Push overlapping dots apart. Grid-bucketed so it stays fast on big graphs. */
  function relax(g, ids, pos, upp, maxPasses) {
    var xs = [], ys = [], rs = [];
    var maxR = 0;
    ids.forEach(function (id, i) {
      xs[i] = pos[id].x;
      ys[i] = pos[id].y;
      rs[i] = radiusOf(g, id, upp);
      if (rs[i] > maxR) maxR = rs[i];
    });
    var cell = maxR * 2 * RELAX_GAP;
    if (!cell) return;
    var pass, i, j, k, moved;
    for (pass = 0; pass < (maxPasses || RELAX_PASSES); pass++) {
      var grid = {};
      moved = false;
      for (i = 0; i < ids.length; i++) {
        var key = Math.floor(xs[i] / cell) + "," + Math.floor(ys[i] / cell);
        (grid[key] = grid[key] || []).push(i);
      }
      for (i = 0; i < ids.length; i++) {
        var cx = Math.floor(xs[i] / cell);
        var cy = Math.floor(ys[i] / cell);
        var dx, dy;
        for (dx = -1; dx <= 1; dx++) {
          for (dy = -1; dy <= 1; dy++) {
            var bucket = grid[(cx + dx) + "," + (cy + dy)];
            if (!bucket) continue;
            for (k = 0; k < bucket.length; k++) {
              j = bucket[k];
              if (j <= i) continue;
              var vx = xs[j] - xs[i];
              var vy = ys[j] - ys[i];
              var dist = Math.sqrt(vx * vx + vy * vy);
              var least = (rs[i] + rs[j]) * RELAX_GAP;
              if (dist >= least) continue;
              if (dist < 1e-9) {
                var angle = ((i * 2654435761) % 360) * (Math.PI / 180);
                vx = Math.cos(angle);
                vy = Math.sin(angle);
                dist = 1;
              }
              var push = (least - dist) / 2;
              var ux = vx / dist;
              var uy = vy / dist;
              xs[i] -= ux * push;
              ys[i] -= uy * push;
              xs[j] += ux * push;
              ys[j] += uy * push;
              moved = true;
            }
          }
        }
      }
      if (!moved) break;
    }
    ids.forEach(function (id, n) {
      pos[id].x = xs[n];
      pos[id].y = ys[n];
    });
  }

  /* Lay pieces out in shelves; returns where each goes and the overall size. */
  function shelves(pieces, gap) {
    var area = 0;
    var widest = 0;
    pieces.forEach(function (p) {
      area += (p.box.w + gap) * (p.box.h + gap);
      widest = Math.max(widest, p.box.w + gap);
    });
    var rowWidth = Math.max(widest, Math.sqrt(area) * 1.25);
    var places = [];
    var x = 0, y = 0, rowHeight = 0, usedWidth = 0;
    pieces.forEach(function (p) {
      if (x > 0 && x + p.box.w > rowWidth) {
        x = 0;
        y += rowHeight + gap;
        rowHeight = 0;
      }
      places.push({ x: x, y: y });
      usedWidth = Math.max(usedWidth, x + p.box.w);
      x += p.box.w + gap;
      rowHeight = Math.max(rowHeight, p.box.h);
    });
    return { places: places, width: usedWidth, height: y + rowHeight };
  }

  /* Arrange disconnected pieces in shelves, biggest first, centred on the origin.
   * The gap is a few node radii at the size the dots will have once the whole
   * layout is fitted to the view, found by repeating the estimate. */
  function pack(g, ids, adj, pos, upp) {
    var parent = {};
    ids.forEach(function (id) { parent[id] = id; });
    function root(id) {
      while (parent[id] !== id) {
        parent[id] = parent[parent[id]];
        id = parent[id];
      }
      return id;
    }
    ids.forEach(function (id) {
      adj[id].forEach(function (other) {
        var a = root(id);
        var b = root(other);
        if (a !== b) parent[a] = b;
      });
    });
    var groups = {};
    ids.forEach(function (id) { (groups[root(id)] = groups[root(id)] || []).push(id); });
    var pieces = Object.keys(groups).map(function (key) {
      return { members: groups[key], box: extent(pos, groups[key]) };
    });
    if (pieces.length < 2) return;
    pieces.sort(function (a, b) { return b.members.length - a.members.length; });

    var view = core.viewport();
    var side = Math.max(1, Math.min(view.width, view.height) * 0.8);
    var meanRadius = ids.reduce(function (sum, id) { return sum + Math.max(1, g.getNodeAttribute(id, "size")); }, 0) / ids.length;
    var scale = upp;
    var plan = null;
    var pass;
    for (pass = 0; pass < 4; pass++) {
      plan = shelves(pieces, PACK_GAP * meanRadius * scale);
      scale = Math.max(plan.width, plan.height, 1e-9) / side;
    }
    pieces.forEach(function (p, i) {
      var shiftX = plan.places[i].x - p.box.minX;
      /* sigma's y axis points up, so negate to put the biggest piece top-left. */
      var shiftY = -plan.places[i].y - p.box.h - p.box.minY;
      p.members.forEach(function (id) {
        pos[id].x += shiftX;
        pos[id].y += shiftY;
      });
    });
    var all = extent(pos, ids);
    var midX = (all.minX + all.maxX) / 2;
    var midY = (all.minY + all.maxY) / 2;
    ids.forEach(function (id) {
      pos[id].x -= midX;
      pos[id].y -= midY;
    });
  }

  /* Dots are a fixed size on screen, so spreading the layout shrinks the view
   * scale and makes dots inside each piece look more crowded. Relaxing and
   * packing therefore alternate at the current scale until they settle. Each
   * round yields to the page first, and big graphs get fewer rounds. */
  function finishOrganic() {
    var g = core.graph();
    var ids = visibleIds(g);
    if (ids.length < 2) { busy = false; return; }
    var started = window.performance.now();
    var adj = adjacency(g, ids);
    var pos = positionsOf(g, ids);
    var rounds = ids.length < 3000 ? TIDY_ROUNDS : (ids.length < 8000 ? 3 : 2);
    var passes = ids.length < 8000 ? RELAX_PASSES : 12;
    fanOut(g, ids, adj, pos, unitsPerPixel(pos, ids));
    var round = 0;

    function next() {
      if (round >= rounds) {
        core.setPositions(pos);
        core.fitCamera();
        stats.postMs = Math.round(window.performance.now() - started);
        core.setStatus("Tidied " + ids.length + " nodes (organic layout).", "ok");
        busy = false;
        return;
      }
      round += 1;
      core.setStatus("Spacing out " + ids.length + " nodes (" + round + " of " + rounds + ")…");
      window.setTimeout(function () {
        relax(g, ids, pos, unitsPerPixel(pos, ids), passes);
        pack(g, ids, adj, pos, unitsPerPixel(pos, ids));
        next();
      }, 0);
    }
    next();
  }

  function organic(ids) {
    var iterations = ids.length < 1500 ? 300 : (ids.length < 6000 ? 200 : 120);
    core.setStatus("Laying out " + ids.length + " nodes…");
    var began = window.performance.now();
    core.runLayout(iterations, { full: true, onDone: function () {
      stats.layoutMs = Math.round(window.performance.now() - began);
      finishOrganic();
    } });
  }

  /* ---------------------------------------------------------------- rings */

  function circularMean(list, pos) {
    var sx = 0, sy = 0, n = 0;
    list.forEach(function (id) {
      if (!pos[id]) return;
      var len = Math.sqrt(pos[id].x * pos[id].x + pos[id].y * pos[id].y);
      if (len < 1e-9) return;
      sx += pos[id].x / len;
      sy += pos[id].y / len;
      n += 1;
    });
    return n ? Math.atan2(sy, sx) : NaN;
  }

  function byLabel(g) {
    return function (a, b) {
      var la = g.getNodeAttribute(a, "full");
      var lb = g.getNodeAttribute(b, "full");
      return la < lb ? -1 : (la > lb ? 1 : 0);
    };
  }

  /* Place a list on concentric bands starting at radius start. Spacing is 1. */
  function placeBands(list, start, pos) {
    var radius = start;
    var index = 0;
    var band = 0;
    if (list.length === 1 && start === 0) {
      pos[list[0]] = { x: 0, y: 0 };
      return 0;
    }
    while (index < list.length) {
      if (radius < 1) radius = 1;
      var capacity = Math.max(1, Math.floor((2 * Math.PI * radius) / 1));
      var take = Math.min(capacity, list.length - index);
      var stagger = band % 2 ? Math.PI / take : 0;
      var i;
      for (i = 0; i < take; i++) {
        var angle = (2 * Math.PI * i) / take + stagger;
        pos[list[index + i]] = { x: Math.cos(angle) * radius, y: Math.sin(angle) * radius };
      }
      index += take;
      band += 1;
      if (index < list.length) radius += 1;
    }
    return radius;
  }

  function rings(g, ids) {
    var adj = adjacency(g, ids);
    var levels = [[], [], [], []];
    ids.forEach(function (id) {
      var type = g.getNodeAttribute(id, "ntype");
      var level = RING_OF[type];
      levels[level === undefined ? 1 : level].push(id);
    });
    var pos = {};
    var radius = 0;
    var compare = byLabel(g);
    levels.forEach(function (list, level) {
      if (!list.length) return;
      var wanted = {};
      list.forEach(function (id) { wanted[id] = circularMean(adj[id], pos); });
      list.sort(function (a, b) {
        var na = isNaN(wanted[a]);
        var nb = isNaN(wanted[b]);
        if (na && nb) return compare(a, b);
        if (na) return 1;
        if (nb) return -1;
        return wanted[a] - wanted[b];
      });
      var start = level === 0 ? (list.length > 1 ? 2 : 0) : radius + 3;
      radius = placeBands(list, start, pos);
    });
    return pos;
  }

  /* ------------------------------------------------------------ hierarchy */

  function hierarchy(g, ids) {
    var adj = adjacency(g, ids);
    var rows = [[], [], [], [], []];
    var compare = byLabel(g);
    ids.forEach(function (id) {
      var row = ROW_OF[g.getNodeAttribute(id, "ntype")];
      rows[row === undefined ? ROW_DEFAULT : row].push(id);
    });
    rows.forEach(function (list) {
      list.sort(function (a, b) {
        var ta = g.getNodeAttribute(a, "ntype");
        var tb = g.getNodeAttribute(b, "ntype");
        return ta < tb ? -1 : (ta > tb ? 1 : compare(a, b));
      });
    });
    var rank = {};
    function ranks(list) {
      list.forEach(function (id, i) { rank[id] = list.length > 1 ? i / (list.length - 1) : 0.5; });
    }
    rows.forEach(ranks);

    function sweep(list, neighbourRows) {
      var wanted = {};
      list.forEach(function (id) {
        var sum = 0, n = 0;
        adj[id].forEach(function (other) {
          if (neighbourRows[other]) { sum += rank[other]; n += 1; }
        });
        wanted[id] = n ? sum / n : rank[id];
      });
      list.sort(function (a, b) { return wanted[a] - wanted[b]; });
      ranks(list);
    }
    function rowSet(list) {
      var set = {};
      list.forEach(function (id) { set[id] = true; });
      return set;
    }
    var pass, r;
    for (pass = 0; pass < 2; pass++) {
      for (r = 1; r < rows.length; r++) sweep(rows[r], rowSet(rows[r - 1]));
      for (r = rows.length - 2; r >= 0; r--) sweep(rows[r], rowSet(rows[r + 1]));
    }

    var pos = {};
    var y = 0;
    rows.forEach(function (list) {
      if (!list.length) return;
      var lines = Math.ceil(list.length / HIERARCHY_LINE);
      var perLine = Math.ceil(list.length / lines);
      var line, i;
      for (line = 0; line < lines; line++) {
        var chunk = list.slice(line * perLine, (line + 1) * perLine);
        for (i = 0; i < chunk.length; i++) {
          pos[chunk[i]] = { x: (i - (chunk.length - 1) / 2) * 1.2, y: y + line * 1.1 };
        }
      }
      y += lines * 1.1 + 5;
    });
    return pos;
  }

  /* ------------------------------------------------------------------- UI */

  function tidy() {
    if (busy) return;
    var g = core.graph();
    var ids = g ? visibleIds(g) : [];
    if (ids.length < 2) {
      core.setStatus("Nothing to tidy: fewer than two nodes are showing.", "warn");
      return;
    }
    var preset = el.preset.value;
    busy = true;
    if (preset === "organic") {
      organic(ids);
      return;
    }
    var pos = preset === "rings" ? rings(g, ids) : hierarchy(g, ids);
    core.stopLayout();
    core.setPositions(pos);
    core.fitCamera();
    core.setStatus("Tidied " + ids.length + " nodes (" + (preset === "rings" ? "rings by kind" : "hierarchy") + ").", "ok");
    busy = false;
  }

  function init() {
    core = window.TitanEye && window.TitanEye.core;
    el.preset = document.getElementById("te-layout-preset");
    el.tidy = document.getElementById("te-tidy");
    if (!core || !el.preset || !el.tidy) return false;
    el.tidy.addEventListener("click", tidy);
    return true;
  }

  return {
    init: init,
    tidy: tidy,
    /* exposed for the measurements in docs/TITANEYE.md */
    measure: function () {
      var g = core.graph();
      var ids = visibleIds(g);
      var pos = positionsOf(g, ids);
      var upp = unitsPerPixel(pos, ids);
      var box = extent(pos, ids);
      var cell = 40 * upp;
      var grid = {};
      var overlaps = 0;
      ids.forEach(function (id, i) {
        var key = Math.floor(pos[id].x / cell) + "," + Math.floor(pos[id].y / cell);
        (grid[key] = grid[key] || []).push(i);
      });
      ids.forEach(function (id, i) {
        var cx = Math.floor(pos[id].x / cell);
        var cy = Math.floor(pos[id].y / cell);
        var dx, dy;
        for (dx = -1; dx <= 1; dx++) {
          for (dy = -1; dy <= 1; dy++) {
            (grid[(cx + dx) + "," + (cy + dy)] || []).forEach(function (j) {
              if (j <= i) return;
              var other = ids[j];
              var d = Math.sqrt(Math.pow(pos[id].x - pos[other].x, 2) + Math.pow(pos[id].y - pos[other].y, 2));
              if (d < (radiusOf(g, id, upp) + radiusOf(g, other, upp))) overlaps += 1;
            });
          }
        }
      });
      return { nodes: ids.length, overlappingPairs: overlaps, width: box.w, height: box.h,
               area: box.w * box.h, unitsPerPixel: upp, layoutMs: stats.layoutMs, postMs: stats.postMs };
    }
  };
})();
