/* TitanEye scale view: how big is this infrastructure?
 *
 * A left drawer over the graph with headline numbers, a hosting-concentration
 * map (ASN -> IP -> sites), ranked tables, clusters of sites that share an
 * indicator, a noise filter for shared infrastructure, and a timeline filter.
 *
 * Everything is computed in the browser from the graph already on screen.
 * Values are scan data, so they are only ever shown with textContent.
 */
window.TitanEyeScale = (function () {
  "use strict";

  var RANK_TYPES = ["ip", "apex_domain", "asn", "wallet", "tls_cert", "file_hash", "third_party",
                    "filename", "text_string", "tag", "contact", "tech", "ptr"];
  /* How strongly a shared indicator suggests one operator. */
  var WEIGHT = { wallet: 5, file_hash: 4, contact: 4, filename: 3, text_string: 3, ip: 2, apex_domain: 1, tag: 1,
                 third_party: 1, asn: 0.5, tls_cert: 0.5, tech: 0.25, ptr: 1 };
  var CLUSTER_DEFAULTS = { wallet: true, file_hash: true, contact: true, filename: true, text_string: true,
                           ip: true, apex_domain: true, tag: true, third_party: false, asn: false,
                           tls_cert: false, tech: false, ptr: false };
  /* A pair of sites sharing something is common; three or more is a pattern. */
  var MIN_CLUSTER_SITES = 3;
  var RANK_ROWS = 25;
  var CLUSTER_ROWS = 40;
  var TREEMAP_ASNS = 8;
  var TREEMAP_IPS = 6;
  var HISTOGRAM_BINS = 40;
  var SLIDER_MAX = 1000;
  var PLAY_MS = 200;
  var PLAY_STEPS = 60;

  var core = null;
  var el = {};
  var state = {
    rankType: "ip",
    clusterTypes: {},
    clusterShareCap: 200,
    timeMin: null,
    timeMax: null,
    playTimer: null,
    tFrom: 0,
    tTo: 1000,
    refreshTimer: null
  };
  Object.keys(CLUSTER_DEFAULTS).forEach(function (type) { state.clusterTypes[type] = CLUSTER_DEFAULTS[type]; });

  function make(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function clip(text, max) {
    text = String(text);
    return text.length > max ? text.slice(0, max - 1) + "…" : text;
  }

  function label(id) {
    var g = core.graph();
    return g && g.hasNode(id) ? g.getNodeAttribute(id, "full") : id;
  }

  function sites(n) {
    return n + (n === 1 ? " site" : " sites");
  }

  function section(title) {
    var box = make("section", "te-drawer__section");
    box.appendChild(make("h3", "te-section__title", title));
    return box;
  }

  function jump(id) {
    core.select(id);
    core.focusNode(id);
  }

  /* ---------------------------------------------------------------- stats */

  function median(numbers) {
    if (!numbers.length) return null;
    numbers.sort(function (a, b) { return a - b; });
    var mid = Math.floor(numbers.length / 2);
    return numbers.length % 2 ? numbers[mid] : (numbers[mid - 1] + numbers[mid]) / 2;
  }

  function collect(g) {
    var counts = {};
    var ages = [];
    var countries = {};
    var times = [];
    g.forEachNode(function (id, attrs) {
      counts[attrs.ntype] = (counts[attrs.ntype] || 0) + 1;
      var data = attrs.data || {};
      if (typeof data.country === "string" && data.country) countries[data.country] = true;
      if (attrs.ntype === "site") {
        if (typeof data.domain_age_days === "number") ages.push(data.domain_age_days);
        var stamp = data.last_seen || data.first_seen;
        if (stamp) times.push(Date.parse(stamp));
      }
    });
    times = times.filter(function (t) { return !isNaN(t); });
    return { counts: counts, medianAge: median(ages), countries: Object.keys(countries).length, times: times };
  }

  function tile(value, name) {
    var t = make("div", "te-tile");
    t.appendChild(make("div", "te-tile__value", value));
    t.appendChild(make("div", "te-tile__name", name));
    return t;
  }

  function histogram(times) {
    var box = make("div", "te-hist");
    if (times.length < 2) {
      box.appendChild(make("p", "te-note", "Scan dates will chart here once the graph has sites with scan times."));
      return box;
    }
    var min = Math.min.apply(null, times);
    var max = Math.max.apply(null, times);
    var span = Math.max(1, max - min);
    var bins = [];
    var i;
    for (i = 0; i < HISTOGRAM_BINS; i++) bins.push(0);
    times.forEach(function (t) {
      var index = Math.min(HISTOGRAM_BINS - 1, Math.floor(((t - min) / span) * HISTOGRAM_BINS));
      bins[index] += 1;
    });
    var top = Math.max.apply(null, bins);
    var bars = make("div", "te-hist__bars");
    bins.forEach(function (count, index) {
      var bar = make("span", "te-hist__bar");
      bar.style.height = Math.max(count ? 4 : 0, Math.round((count / top) * 100)) + "%";
      var from = new Date(min + (span * index) / HISTOGRAM_BINS).toISOString().slice(0, 10);
      bar.title = from + ": " + count + " sites";
      bars.appendChild(bar);
    });
    box.appendChild(bars);
    var axis = make("div", "te-hist__axis");
    axis.appendChild(make("span", null, new Date(min).toISOString().slice(0, 10)));
    axis.appendChild(make("span", null, "Scans over time (by last scan)"));
    axis.appendChild(make("span", null, new Date(max).toISOString().slice(0, 10)));
    box.appendChild(axis);
    return box;
  }

  function renderOverview(body, info) {
    var box = section("Overview");
    var grid = make("div", "te-tiles");
    var c = info.counts;
    grid.appendChild(tile(String(c.site || 0), "Sites"));
    grid.appendChild(tile(String(c.ip || 0), "IPs"));
    grid.appendChild(tile(String(c.apex_domain || 0), "Apex domains"));
    grid.appendChild(tile(String(c.asn || 0), "ASNs"));
    grid.appendChild(tile(String(info.countries), "Countries"));
    grid.appendChild(tile(String(c.wallet || 0), "Wallets"));
    grid.appendChild(tile(info.medianAge === null ? "n/a" : Math.round(info.medianAge) + " d", "Median domain age"));
    box.appendChild(grid);
    box.appendChild(histogram(info.times));
    body.appendChild(box);
  }

  /* ------------------------------------------------- hosting concentration */

  function hostingGroups(g) {
    var groups = [];
    g.forEachNode(function (asnId, attrs) {
      if (attrs.ntype !== "asn") return;
      var sites = {};
      var ips = [];
      core.siteNeighbours(asnId).forEach(function (s) { sites[s] = true; });
      g.forEachNeighbor(asnId, function (other, otherAttrs) {
        if (otherAttrs.ntype !== "ip") return;
        var list = core.siteNeighbours(other);
        list.forEach(function (s) { sites[s] = true; });
        ips.push({ id: other, count: list.length });
      });
      var total = Object.keys(sites).length;
      if (total) {
        ips.sort(function (a, b) { return b.count - a.count; });
        groups.push({ id: asnId, total: total, ips: ips });
      }
    });
    groups.sort(function (a, b) { return b.total - a.total; });
    return groups;
  }

  function renderTreemap(body, g) {
    var box = section("Hosting concentration");
    var groups = hostingGroups(g).slice(0, TREEMAP_ASNS);
    if (!groups.length) {
      box.appendChild(make("p", "te-note", "Add sites that have IP and ASN data to see where they are hosted."));
      body.appendChild(box);
      return;
    }
    box.appendChild(make("p", "te-note", "Each block is an ASN, sized by the sites on it; the stripes inside are its busiest IPs. Click one to select it."));
    var map = make("div", "te-tm");
    groups.forEach(function (group, index) {
      var cell = make("div", "te-tm__asn te-tm__asn--" + (index % 4));
      cell.style.flexGrow = String(group.total);
      var head = make("button", "te-tm__head");
      head.type = "button";
      head.appendChild(make("span", "te-tm__name", clip(label(group.id), 22)));
      head.appendChild(make("span", "te-tm__count", sites(group.total)));
      head.addEventListener("click", function () { jump(group.id); });
      cell.appendChild(head);
      var stack = make("div", "te-tm__ips");
      var shown = group.ips.slice(0, TREEMAP_IPS);
      shown.forEach(function (ip) {
        var seg = make("button", "te-tm__ip");
        seg.type = "button";
        seg.style.flexGrow = String(Math.max(1, ip.count));
        seg.title = label(ip.id) + ": " + sites(ip.count);
        seg.appendChild(make("span", null, clip(label(ip.id), 18) + "  " + ip.count));
        seg.addEventListener("click", function () { jump(ip.id); });
        stack.appendChild(seg);
      });
      var rest = group.ips.length - shown.length;
      if (rest > 0) stack.appendChild(make("div", "te-tm__more", "+ " + rest + " more IPs"));
      cell.appendChild(stack);
      map.appendChild(cell);
    });
    box.appendChild(map);
    body.appendChild(box);
  }

  /* ------------------------------------------------------------- rankings */

  function rankRows(g, type) {
    var rows = [];
    g.forEachNode(function (id, attrs) {
      if (attrs.ntype !== type) return;
      var count = type === "site" ? 0 : core.siteNeighbours(id).length;
      if (count) rows.push({ id: id, count: count });
    });
    rows.sort(function (a, b) { return b.count - a.count; });
    return rows;
  }

  function renderRankings(body, g) {
    var box = section("Rankings");
    var picker = make("select", "field te-drawer__select");
    picker.setAttribute("aria-label", "Rank by");
    RANK_TYPES.forEach(function (type) {
      var option = make("option", null, core.TYPES[type].label + "s by sites");
      option.value = type;
      if (type === state.rankType) option.selected = true;
      picker.appendChild(option);
    });
    picker.addEventListener("change", function () {
      state.rankType = picker.value;
      refresh();
    });
    box.appendChild(picker);
    var rows = rankRows(g, state.rankType);
    if (!rows.length) {
      box.appendChild(make("p", "te-note", "Nothing of this type is linked to a site yet."));
    } else {
      var table = make("table", "te-rank");
      rows.slice(0, RANK_ROWS).forEach(function (row, index) {
        var tr = make("tr");
        tr.appendChild(make("td", "te-rank__n", String(index + 1)));
        var cell = make("td");
        var button = make("button", "te-rank__link", clip(label(row.id), 44));
        button.type = "button";
        button.title = label(row.id);
        button.addEventListener("click", function () { jump(row.id); });
        cell.appendChild(button);
        tr.appendChild(cell);
        tr.appendChild(make("td", "te-rank__count", String(row.count)));
        table.appendChild(tr);
      });
      box.appendChild(table);
      if (rows.length > RANK_ROWS) box.appendChild(make("p", "te-note", "Top " + RANK_ROWS + " of " + rows.length + "."));
    }
    body.appendChild(box);
  }

  /* ------------------------------------------------------------- clusters */

  function findClusters(g) {
    var parent = {};
    function root(id) {
      while (parent[id] !== id) {
        parent[id] = parent[parent[id]];
        id = parent[id];
      }
      return id;
    }
    function add(id) { if (parent[id] === undefined) parent[id] = id; }
    function union(a, b) {
      add(a);
      add(b);
      var ra = root(a);
      var rb = root(b);
      if (ra !== rb) parent[ra] = rb;
    }
    var shareCache = {};
    function shares(id) {
      if (shareCache[id] === undefined) shareCache[id] = core.siteNeighbours(id).length;
      return shareCache[id];
    }

    g.forEachEdge(function (edge, attrs, source, target) {
      var a = g.getNodeAttribute(source, "ntype");
      var b = g.getNodeAttribute(target, "ntype");
      var site = a === "site" ? source : (b === "site" ? target : null);
      var other = site === source ? target : source;
      if (!site || (a === "site" && b === "site")) return;
      var type = g.getNodeAttribute(other, "ntype");
      if (!state.clusterTypes[type] || shares(other) > state.clusterShareCap) return;
      union(site, other);
    });

    var groups = {};
    Object.keys(parent).forEach(function (id) {
      var r = root(id);
      (groups[r] = groups[r] || []).push(id);
    });

    var clusters = [];
    Object.keys(groups).forEach(function (r) {
      var members = groups[r];
      var sites = members.filter(function (id) { return g.getNodeAttribute(id, "ntype") === "site"; });
      if (sites.length < MIN_CLUSTER_SITES) return;
      var memberSet = {};
      members.forEach(function (id) { memberSet[id] = true; });
      var evidence = [];
      members.forEach(function (id) {
        var type = g.getNodeAttribute(id, "ntype");
        if (type === "site") return;
        var inside = core.siteNeighbours(id).filter(function (s) { return memberSet[s]; }).length;
        if (inside >= 2) evidence.push({ id: id, type: type, sites: inside, score: (WEIGHT[type] || 1) * (inside - 1) });
      });
      evidence.sort(function (a, b) { return b.score - a.score; });
      var score = evidence.reduce(function (sum, e) { return sum + e.score; }, 0);
      clusters.push({ sites: sites, members: members, evidence: evidence, score: score });
    });
    clusters.sort(function (a, b) { return b.score - a.score || b.sites.length - a.sites.length; });
    return clusters;
  }

  function renderClusters(body, g) {
    var box = section("Clusters");
    box.appendChild(make("p", "te-note",
      "Sites that share a linking indicator are grouped, and a cluster needs at least " + MIN_CLUSTER_SITES + " sites. Stronger indicators (wallets, file hashes, contacts) rank higher."));
    var checks = make("div", "te-checks");
    Object.keys(CLUSTER_DEFAULTS).forEach(function (type) {
      var label = make("label", "te-checks__item");
      var input = make("input");
      input.type = "checkbox";
      input.checked = !!state.clusterTypes[type];
      input.addEventListener("change", function () {
        state.clusterTypes[type] = input.checked;
        refresh();
      });
      label.appendChild(input);
      label.appendChild(make("span", null, core.TYPES[type].label));
      checks.appendChild(label);
    });
    box.appendChild(checks);

    var cap = make("label", "te-field-row");
    cap.appendChild(make("span", null, "Ignore indicators shared by more than"));
    var capInput = make("input", "field te-field-row__num");
    capInput.type = "number";
    capInput.min = "2";
    capInput.value = String(state.clusterShareCap);
    capInput.addEventListener("change", function () {
      var n = parseInt(capInput.value, 10);
      state.clusterShareCap = n >= 2 ? n : 200;
      refresh();
    });
    cap.appendChild(capInput);
    cap.appendChild(make("span", null, "sites"));
    box.appendChild(cap);

    var clearButton = make("button", "btn btn--ghost btn--small", "Clear highlight");
    clearButton.type = "button";
    clearButton.addEventListener("click", function () { core.clearHighlight(); });
    box.appendChild(clearButton);

    var clusters = findClusters(g);
    if (!clusters.length) {
      box.appendChild(make("p", "te-note", "No group of " + MIN_CLUSTER_SITES + " or more sites shares one of the chosen indicators yet."));
    } else {
      box.appendChild(make("p", "te-note", clusters.length + " clusters" + (clusters.length > CLUSTER_ROWS ? " (top " + CLUSTER_ROWS + " shown)" : "") + "."));
      clusters.slice(0, CLUSTER_ROWS).forEach(function (cluster, index) {
        var card = make("div", "te-cluster");
        var head = make("div", "te-cluster__head");
        head.appendChild(make("strong", null, "Cluster " + (index + 1)));
        head.appendChild(make("span", "te-note", sites(cluster.sites.length) + ", " + cluster.evidence.length + " shared indicator" + (cluster.evidence.length === 1 ? "" : "s")));
        card.appendChild(head);
        cluster.evidence.slice(0, 4).forEach(function (e) {
          var line = make("button", "te-cluster__ev");
          line.type = "button";
          line.appendChild(make("span", "te-cluster__type", core.TYPES[e.type].label));
          line.appendChild(make("span", "te-cluster__val", clip(label(e.id), 40)));
          line.appendChild(make("span", "te-cluster__n", sites(e.sites)));
          line.addEventListener("click", function () { jump(e.id); });
          card.appendChild(line);
        });
        var show = make("button", "btn btn--small", "Highlight cluster");
        show.type = "button";
        show.addEventListener("click", function () {
          core.highlight(cluster.members, cluster.evidence.length ? cluster.evidence[0].id : cluster.sites[0]);
          core.focusNode(cluster.evidence.length ? cluster.evidence[0].id : cluster.sites[0]);
        });
        card.appendChild(show);
        box.appendChild(card);
      });
    }
    body.appendChild(box);
  }

  /* ------------------------------------------------------ filters (graph) */

  function dayLabel(ms) {
    return new Date(ms).toISOString().slice(0, 10);
  }

  function renderFilters(body, g, info) {
    var box = section("Filters");

    /* Noise: hide infrastructure that too many sites share. */
    var most = 0;
    g.forEachNode(function (id, attrs) {
      if (["ip", "asn", "tls_cert", "tech", "third_party", "ptr", "cidr"].indexOf(attrs.ntype) !== -1) {
        most = Math.max(most, core.siteNeighbours(id).length);
      }
    });
    var noiseWrap = make("div", "te-filter");
    var noiseLabel = make("label", "te-filter__label");
    noiseLabel.setAttribute("for", "te-noise");
    var noiseText = make("span", null, "Hide shared infrastructure");
    var noiseValue = make("span", "te-filter__value", "Off");
    noiseLabel.appendChild(noiseText);
    noiseLabel.appendChild(noiseValue);
    var noise = make("input");
    noise.type = "range";
    noise.id = "te-noise";
    noise.min = "1";
    noise.max = String(Math.max(2, most + 1));
    noise.value = noise.max;
    if (state.noiseMax !== undefined && state.noiseMax !== null && state.noiseMax <= most) noise.value = String(state.noiseMax);
    noise.disabled = most < 2;
    function paintNoise() {
      var off = parseInt(noise.value, 10) > most;
      noiseValue.textContent = off ? "Off" : "more than " + noise.value + " sites";
    }
    noise.addEventListener("input", function () {
      var n = parseInt(noise.value, 10);
      state.noiseMax = n > most ? null : n;
      core.setNoiseMax(state.noiseMax);
      paintNoise();
    });
    paintNoise();
    noiseWrap.appendChild(noiseLabel);
    noiseWrap.appendChild(noise);
    noiseWrap.appendChild(make("p", "te-note",
      "Hides IPs, ASNs, TLS issuers, technologies, third parties and reverse-DNS names that more than this many sites share."));
    box.appendChild(noiseWrap);

    /* Timeline. */
    var times = info.times;
    var timeWrap = make("div", "te-filter");
    if (times.length < 2) {
      timeWrap.appendChild(make("p", "te-note", "The timeline needs sites with scan times. Run an expansion to add some."));
      box.appendChild(timeWrap);
      body.appendChild(box);
      return;
    }
    var min = Math.min.apply(null, times);
    var max = Math.max.apply(null, times);
    state.timeMin = min;
    state.timeMax = max;
    var timeLabel = make("div", "te-filter__label");
    timeLabel.appendChild(make("span", null, "Timeline"));
    var timeValue = make("span", "te-filter__value", dayLabel(min + ((max - min) * state.tFrom) / SLIDER_MAX) + " to " + dayLabel(min + ((max - min) * state.tTo) / SLIDER_MAX));
    timeLabel.appendChild(timeValue);
    timeWrap.appendChild(timeLabel);

    function slider(name) {
      var input = make("input");
      input.type = "range";
      input.min = "0";
      input.max = String(SLIDER_MAX);
      input.setAttribute("aria-label", name);
      return input;
    }
    var from = slider("Timeline start");
    var to = slider("Timeline end");
    from.value = String(state.tFrom);
    to.value = String(state.tTo);
    function at(input) { return min + ((max - min) * parseInt(input.value, 10)) / SLIDER_MAX; }
    function applyTime() {
      var a = parseInt(from.value, 10);
      var b = parseInt(to.value, 10);
      if (a > b) {
        from.value = String(b);
        a = b;
      }
      state.tFrom = a;
      state.tTo = b;
      timeValue.textContent = dayLabel(at(from)) + " to " + dayLabel(at(to));
      if (a === 0 && b === SLIDER_MAX) core.setTimeRange(null, null);
      else core.setTimeRange(new Date(at(from)).toISOString(), new Date(at(to) + 86399999).toISOString());
    }
    from.addEventListener("input", applyTime);
    to.addEventListener("input", applyTime);
    timeWrap.appendChild(from);
    timeWrap.appendChild(to);

    var buttons = make("div", "te-filter__buttons");
    var play = make("button", "btn btn--small", "Play growth");
    play.type = "button";
    var reset = make("button", "btn btn--ghost btn--small", "Reset");
    reset.type = "button";
    function stopPlay() {
      if (state.playTimer) window.clearInterval(state.playTimer);
      state.playTimer = null;
      play.textContent = "Play growth";
    }
    play.addEventListener("click", function () {
      if (state.playTimer) { stopPlay(); return; }
      from.value = "0";
      to.value = "0";
      applyTime();
      play.textContent = "Stop";
      state.playTimer = window.setInterval(function () {
        var next = parseInt(to.value, 10) + Math.ceil(SLIDER_MAX / PLAY_STEPS);
        if (next >= SLIDER_MAX) {
          to.value = String(SLIDER_MAX);
          applyTime();
          stopPlay();
          return;
        }
        to.value = String(next);
        applyTime();
      }, PLAY_MS);
    });
    reset.addEventListener("click", function () {
      stopPlay();
      from.value = "0";
      to.value = String(SLIDER_MAX);
      applyTime();
    });
    buttons.appendChild(play);
    buttons.appendChild(reset);
    timeWrap.appendChild(buttons);
    timeWrap.appendChild(make("p", "te-note",
      "Shows only sites scanned in the range; their infrastructure disappears with them. Imported sites with no scan time always show."));
    box.appendChild(timeWrap);
    body.appendChild(box);
  }

  /* ---------------------------------------------------------------- panel */

  function refresh() {
    if (el.root.hidden) return;
    var g = core.graph();
    var scroll = el.root.scrollTop;
    clear(el.body);
    if (!g || !g.order) {
      el.body.appendChild(make("p", "te-note", "The graph is empty. Expand a node or import a dataset, then come back here."));
      return;
    }
    var info = collect(g);
    renderOverview(el.body, info);
    renderFilters(el.body, g, info);
    renderTreemap(el.body, g);
    renderRankings(el.body, g);
    renderClusters(el.body, g);
    el.root.scrollTop = scroll;
  }

  function scheduleRefresh() {
    if (el.root.hidden) return;
    window.clearTimeout(state.refreshTimer);
    state.refreshTimer = window.setTimeout(refresh, 400);
  }

  function open() {
    el.root.hidden = false;
    refresh();
  }

  function close() {
    el.root.hidden = true;
    core.clearHighlight();
  }

  function init() {
    core = window.TitanEye && window.TitanEye.core;
    el.root = document.getElementById("te-scale");
    el.body = document.getElementById("te-scale-body");
    var openButton = document.getElementById("te-scale-open");
    if (!core || !el.root || !el.body || !openButton) return false;
    state.noiseMax = null;
    openButton.addEventListener("click", function () { if (el.root.hidden) open(); else close(); });
    document.getElementById("te-scale-close").addEventListener("click", close);
    document.getElementById("te-scale-refresh").addEventListener("click", refresh);
    core.onChange(scheduleRefresh);
    return true;
  }

  return { init: init, open: open, close: close, refresh: refresh };
})();
