/* TitanEye crawler: map out an infrastructure from the selected node.
 *
 * A bounded breadth-first walk. Each step runs one expansion (the same
 * /api/graph/expand route the buttons use), merges the result, and queues the
 * new indicators that are worth following. It is capped on depth, requests and
 * nodes, spaces its requests out, stops on a rate limit, and can be resumed.
 */
window.TitanEyeCrawl = (function () {
  "use strict";

  /* Free transform to use for each node type, and the Pro one where there is no free one. */
  var FREE = {
    ip: "ip_sites", apex_domain: "apex_sites", asn: "asn_sites", file_hash: "hash_sites",
    filename: "filename_sites", third_party: "third_party_sites", tag: "tag_sites",
    ptr: "ptr_sites", tls_cert: "cert_sites", tech: "server_sites"
  };
  var PRO = { contact: "contact_sites", wallet: "wallet_sites", text_string: "text_sites", brand: "brand_sites" };
  var FOLLOW_DEFAULT = { ip: true, apex_domain: true, file_hash: true, filename: true };
  var FOLLOW_ORDER = ["ip", "apex_domain", "file_hash", "filename", "third_party", "tag", "contact", "wallet",
                      "text_string", "asn", "tls_cert", "tech", "ptr"];
  var RATE_CODES = { rate_limited: true, local_rate_limited: true };
  var LAYOUT_EVERY = 5;
  var MAX_CONSECUTIVE_ERRORS = 3;

  var core = null;
  var el = {};
  var cfg = { depth: 2, requests: 30, nodes: 3000, size: 100, delay: 2000, hubCap: 300, pro: false, follow: {} };
  var run = null;

  FOLLOW_ORDER.forEach(function (type) { cfg.follow[type] = !!FOLLOW_DEFAULT[type]; });

  function make(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function valueOf(id) {
    return id.slice(id.indexOf(":") + 1);
  }

  function transformFor(type) {
    var id = FREE[type] || (cfg.pro ? PRO[type] : null);
    if (!id) return null;
    var found = core.transforms().filter(function (t) { return t.id === id; })[0];
    return found ? id : null;
  }

  function say(message, tone) {
    el.status.textContent = message;
    el.status.className = "te-note" + (tone ? " te-note--" + tone : "");
  }

  function setButtons() {
    var running = !!(run && run.active);
    var resumable = !!(run && !run.active && run.queue.length);
    el.start.disabled = running;
    el.stop.hidden = !running;
    el.resume.hidden = !resumable;
  }

  /* --------------------------------------------------------------- queue */

  function enqueue(id, depth) {
    var g = core.graph();
    if (!g.hasNode(id)) return;
    var type = g.getNodeAttribute(id, "ntype");
    var transform = transformFor(type);
    if (!transform) return;
    var key = transform + "|" + valueOf(id);
    if (run.seen[key]) return;
    run.seen[key] = true;
    run.queue.push({ id: id, transform: transform, value: valueOf(id), depth: depth });
  }

  function seedQueue(seedId) {
    var g = core.graph();
    var type = g.getNodeAttribute(seedId, "ntype");
    if (type === "site") {
      /* A site is not expandable itself; start from the indicators around it. */
      g.forEachNeighbor(seedId, function (other, attrs) {
        if (cfg.follow[attrs.ntype]) enqueue(other, 1);
      });
    } else {
      var transform = transformFor(type);
      if (!transform) return false;
      enqueue(seedId, 1);
    }
    return run.queue.length > 0;
  }

  /* ---------------------------------------------------------------- loop */

  function finish(reason, tone) {
    run.active = false;
    core.updateCounts();
    core.runLayout(80);
    var left = run.queue.length;
    say(reason + " " + run.requests + " requests, " + run.added + " new nodes" +
        (left ? ", " + left + " expansions still queued (Resume continues)." : "."), tone);
    setButtons();
  }

  function step() {
    if (!run || !run.active) return;
    var g = core.graph();
    if (!run.queue.length) return finish("Crawl finished.", "ok");
    if (run.spent >= cfg.requests) return finish("Stopped at the request limit.", "warn");
    if (g.order >= cfg.nodes) return finish("Stopped at the node limit.", "warn");

    var item = run.queue.shift();
    run.spent += 1;
    run.requests += 1;
    say("Request " + run.spent + " of " + cfg.requests + ", depth " + item.depth + ": " +
        item.transform + " " + (item.value.length > 40 ? item.value.slice(0, 39) + "…" : item.value) +
        ". " + g.order + " nodes so far.");

    core.api("POST", "/api/graph/expand", { transform: item.transform, value: item.value, size: cfg.size })
      .then(function (data) {
        run.errors = 0;
        var fresh = [];
        (data.nodes || []).forEach(function (n) { if (!g.hasNode(n.id)) fresh.push(n); });
        var added = core.merge(data, item.id, "urlscan");
        run.added += added.nodes;
        if (item.depth < cfg.depth) {
          fresh.forEach(function (n) {
            if (!cfg.follow[n.type]) return;
            if (core.siteNeighbours(n.id).length > cfg.hubCap) return;
            enqueue(n.id, item.depth + 1);
          });
        }
        if (run.requests % LAYOUT_EVERY === 0) {
          core.updateCounts();
          core.runLayout(40);
        }
      }, function (err) {
        if (RATE_CODES[err.code]) {
          run.queue.unshift(item);
          run.spent -= 1;
          run.requests -= 1;
          run.seen[item.transform + "|" + item.value] = true;
          finish("Paused by a rate limit (" + err.message + ")", "warn");
          return "paused";
        }
        run.errors += 1;
        run.problems += 1;
        if (run.errors >= MAX_CONSECUTIVE_ERRORS) {
          finish("Stopped after repeated errors (" + err.message + ").", "error");
          return "stopped";
        }
        return null;
      })
      .then(function (outcome) {
        if (outcome === "paused" || outcome === "stopped" || !run.active) return;
        window.setTimeout(step, cfg.delay);
      });
  }

  function start() {
    var g = core.graph();
    var seed = core.selected();
    if (!g || !seed) {
      say("Click a node in the graph first. The crawl starts from it.", "warn");
      return;
    }
    run = { active: true, queue: [], seen: {}, requests: 0, spent: 0, added: 0, errors: 0, problems: 0 };
    if (!seedQueue(seed)) {
      run = null;
      say("There is nothing to expand from that node with the chosen types" +
          (cfg.pro ? "." : ". Try including Pro transforms or more indicator types."), "warn");
      setButtons();
      return;
    }
    setButtons();
    step();
  }

  function resume() {
    if (!run || run.active || !run.queue.length) return;
    run.active = true;
    run.spent = 0;
    run.errors = 0;
    setButtons();
    step();
  }

  function stop() {
    if (run && run.active) finish("Cancelled.", "warn");
  }

  /* ------------------------------------------------------------------ UI */

  function numberField(labelText, key, min, max) {
    var label = make("label", "te-field-row");
    label.appendChild(make("span", null, labelText));
    var input = make("input", "field te-field-row__num");
    input.type = "number";
    input.min = String(min);
    input.max = String(max);
    input.value = String(cfg[key]);
    input.addEventListener("change", function () {
      var n = parseInt(input.value, 10);
      cfg[key] = n >= min && n <= max ? n : cfg[key];
      input.value = String(cfg[key]);
    });
    label.appendChild(input);
    return label;
  }

  function build() {
    var box = el.slot;
    box.appendChild(make("p", "te-note",
      "The crawl is capped, spaced out to respect the search limit, and can be cancelled or resumed."));

    box.appendChild(numberField("Depth (1-3)", "depth", 1, 3));
    box.appendChild(numberField("Most requests", "requests", 1, 500));
    box.appendChild(numberField("Stop at this many nodes", "nodes", 100, 50000));
    box.appendChild(numberField("Seconds between requests", "delay", 1, 30));
    box.appendChild(numberField("Skip indicators shared by more than", "hubCap", 2, 100000));
    /* The delay field is in seconds; store milliseconds. */
    var delayInput = box.querySelectorAll("input")[3];
    delayInput.value = String(cfg.delay / 1000);
    delayInput.addEventListener("change", function () {
      var seconds = parseInt(delayInput.value, 10);
      cfg.delay = (seconds >= 1 && seconds <= 30 ? seconds : 2) * 1000;
      delayInput.value = String(cfg.delay / 1000);
    });

    var size = make("label", "te-field-row");
    size.appendChild(make("span", null, "Results per expansion"));
    var sizeSelect = make("select", "field te-field-row__num");
    [25, 50, 100, 250, 500, 1000, 5000, 10000].forEach(function (n) {
      var option = make("option", null, String(n));
      option.value = String(n);
      if (n === cfg.size) option.selected = true;
      sizeSelect.appendChild(option);
    });
    sizeSelect.addEventListener("change", function () { cfg.size = parseInt(sizeSelect.value, 10); });
    size.appendChild(sizeSelect);
    box.appendChild(size);

    var follow = make("div", "te-checks");
    FOLLOW_ORDER.forEach(function (type) {
      var label = make("label", "te-checks__item");
      var input = make("input");
      input.type = "checkbox";
      input.checked = cfg.follow[type];
      input.addEventListener("change", function () { cfg.follow[type] = input.checked; });
      label.appendChild(input);
      label.appendChild(make("span", null, core.TYPES[type].label + (PRO[type] ? " (Pro)" : "")));
      follow.appendChild(label);
    });
    box.appendChild(make("p", "te-note", "Follow these indicators:"));
    box.appendChild(follow);

    var pro = make("label", "te-checks__item");
    var proInput = make("input");
    proInput.type = "checkbox";
    proInput.addEventListener("change", function () { cfg.pro = proInput.checked; });
    pro.appendChild(proInput);
    pro.appendChild(make("span", null, "Include Pro-plan transforms"));
    box.appendChild(pro);

    var buttons = make("div", "te-filter__buttons");
    el.start = make("button", "btn btn--primary btn--small", "Crawl from selected node");
    el.start.type = "button";
    el.stop = make("button", "btn btn--small", "Cancel");
    el.stop.type = "button";
    el.stop.hidden = true;
    el.resume = make("button", "btn btn--small", "Resume");
    el.resume.type = "button";
    el.resume.hidden = true;
    el.start.addEventListener("click", start);
    el.stop.addEventListener("click", stop);
    el.resume.addEventListener("click", resume);
    buttons.appendChild(el.start);
    buttons.appendChild(el.stop);
    buttons.appendChild(el.resume);
    box.appendChild(buttons);

    el.status = make("p", "te-note");
    el.status.setAttribute("aria-live", "polite");
    box.appendChild(el.status);
  }

  function init() {
    core = window.TitanEye && window.TitanEye.core;
    el.slot = document.getElementById("te-crawl-slot");
    if (!core || !el.slot) return false;
    build();
    /* The crawl starts from the selected node, so it lives in that node's detail panel
     * (the right-hand panel shows the scale view while nothing is selected). */
    el.slot.hidden = false;
    var wrap = make("details", "te-section te-crawl");
    wrap.appendChild(make("summary", "te-crawl__summary", "Crawl outward from this node"));
    wrap.appendChild(el.slot);
    core.addDetailSection(function () { return wrap; });
    return true;
  }

  return { init: init };
})();
