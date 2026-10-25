/* TitanEye wallet intel: basic on-chain facts for wallet nodes.
 *
 * Provider keys are typed into the Keys panel and kept in the `keys` variable
 * below, nothing else. They are never written to localStorage, sessionStorage,
 * IndexedDB, cookies, case files, exports or the URL, and the inputs are
 * emptied as soon as a key is saved. A reload forgets them.
 *
 * Each lookup sends the key to this server as a header; the server uses it for
 * that one request and keeps nothing. Provider data is third-party text, so it
 * is only ever shown with textContent.
 */
window.TitanEyeWallet = (function () {
  "use strict";

  var CHAIN_LABELS = {
    eth: "Ethereum", bsc: "BNB Smart Chain", matic: "Polygon", arb: "Arbitrum",
    avax: "Avalanche", op: "Optimism", btc: "Bitcoin", trx: "Tron"
  };
  var PROVIDERS = {
    etherscan:  { label: "Etherscan",      header: "X-Etherscan-Key", needsKey: true,  chains: ["eth", "bsc", "matic", "arb", "avax", "op"] },
    blockchain: { label: "Blockchain.com", header: "X-Blockchain-Key", needsKey: false, chains: ["btc"] },
    tronscan:   { label: "Tronscan",       header: "X-Tronscan-Key",  needsKey: true,  chains: ["trx"] }
  };

  /* Memory only. See the note at the top of this file. */
  var keys = { etherscan: "", blockchain: "", tronscan: "" };

  var core = null;
  var el = {};
  var pending = {};

  function make(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function providerFor(chain) {
    var name;
    for (name in PROVIDERS) {
      if (PROVIDERS[name].chains.indexOf(chain) !== -1) return name;
    }
    return null;
  }

  /* Nodes from a urlscan expansion carry no chain list; guess from the format. */
  function guessChains(address) {
    if (/^0x[0-9a-fA-F]{40}$/.test(address)) return ["eth"];
    if (/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(address)) return ["trx"];
    if (/^(?:bc1|[13])[0-9A-Za-z]{25,62}$/.test(address)) return ["btc"];
    return [];
  }

  function copyButton(text) {
    var button = make("button", "btn btn--ghost btn--small", "Copy");
    button.type = "button";
    button.addEventListener("click", function () {
      try {
        navigator.clipboard.writeText(text).then(function () {
          button.textContent = "Copied";
          window.setTimeout(function () { button.textContent = "Copy"; }, 1200);
        }, function () { button.textContent = "Copy failed"; });
      } catch (err) {
        button.textContent = "Copy failed";
      }
    });
    return button;
  }

  function fact(name, value) {
    var wrap = make("div", "te-fact");
    wrap.appendChild(make("dt", null, name));
    wrap.appendChild(make("dd", null, value));
    return wrap;
  }

  function renderSummary(summary, cachedAt) {
    var list = make("dl", "te-facts");
    var symbol = summary.native_symbol || "";
    list.appendChild(fact("Address type", summary.address_type || "Unknown"));
    list.appendChild(fact("Balance", summary.balance + " " + symbol));
    if (summary.total_received !== null && summary.total_received !== undefined) {
      list.appendChild(fact("Total received", summary.total_received + " " + symbol));
      list.appendChild(fact("Total sent", summary.total_sent + " " + symbol));
    }
    if (typeof summary.tx_count === "number") {
      var count = String(summary.tx_count);
      if (typeof summary.tx_in === "number") count += " (" + summary.tx_in + " in, " + summary.tx_out + " out)";
      list.appendChild(fact("Transactions", count));
    }
    if (typeof summary.sent_tx_count === "number") list.appendChild(fact("Sent transactions", String(summary.sent_tx_count)));
    list.appendChild(fact("First seen", summary.first_seen || "Not available"));
    list.appendChild(fact("Last seen", summary.last_seen || "Not available"));
    if (summary.contract_name) {
      list.appendChild(fact("Contract", summary.contract_name + (summary.contract_verified ? " (source verified)" : " (not verified)")));
    } else if (summary.is_contract) {
      list.appendChild(fact("Contract", summary.contract_verified ? "Source verified" : "Not verified"));
    }
    (summary.token_balances || []).forEach(function (token) {
      list.appendChild(fact("Holds", token.balance + " " + (token.symbol || token.name)));
    });
    if ((summary.tokens_seen || []).length) {
      list.appendChild(fact("Tokens in recent transfers",
        summary.tokens_seen.map(function (t) { return t.symbol || t.name; }).join(", ")));
    }
    (summary.tags || []).forEach(function (tag) { list.appendChild(fact("Tag", tag)); });

    var url = make("div", "te-fact");
    url.appendChild(make("dt", null, "Explorer"));
    var cell = make("dd", "te-fact__url");
    cell.appendChild(make("code", null, summary.explorer_url));
    cell.appendChild(copyButton(summary.explorer_url));
    url.appendChild(cell);
    list.appendChild(url);

    var source = (PROVIDERS[summary.provider] || { label: summary.provider }).label;
    var age = "";
    if (typeof cachedAt === "number") {
      var minutes = Math.max(0, Math.round((Date.now() / 1000 - cachedAt) / 60));
      age = minutes < 1 ? ", just now" : ", " + minutes + " min ago";
    }
    list.appendChild(fact("Source", source + " (external data" + age + ")"));
    return list;
  }

  /* ----------------------------------------------------------------- lookup */

  function lookup(nodeId, chain, address, status, button) {
    var name = providerFor(chain);
    var provider = PROVIDERS[name];
    if (provider.needsKey && !keys[name]) {
      status.textContent = "Add your " + provider.label + " key first (Keys button in the top bar).";
      return;
    }
    var token = nodeId + "|" + chain;
    if (pending[token]) return;
    pending[token] = true;
    button.disabled = true;
    status.textContent = "Looking up on " + provider.label + "…";

    var headers = { "Content-Type": "application/json", "Accept": "application/json" };
    if (keys[name]) headers[provider.header] = keys[name];
    fetch("/api/chain/summary", {
      method: "POST", headers: headers, body: JSON.stringify({ chain: chain, address: address })
    }).then(function (response) {
      return response.json().then(function (data) {
        if (!response.ok || !data || data.ok === false) {
          var error = (data && data.error) || {};
          var failure = new Error(error.message || "Lookup failed (HTTP " + response.status + ").");
          failure.retryAfter = error.retry_after;
          throw failure;
        }
        return data;
      });
    }).then(function (data) {
      var graph = core.graph();
      var existing = graph && graph.hasNode(nodeId) ? (graph.getNodeAttribute(nodeId, "data").onchain || {}) : {};
      var merged = {};
      Object.keys(existing).forEach(function (k) { merged[k] = existing[k]; });
      merged[chain] = { summary: data.summary, cached_at: data.meta.cached_at };
      core.setNodeData(nodeId, "onchain", merged);
    }).catch(function (err) {
      status.textContent = err.message + (err.retryAfter ? " Try again in " + err.retryAfter + " seconds." : "");
    }).then(function () {
      delete pending[token];
      button.disabled = false;
    });
  }

  function detailSection(ctx) {
    if (ctx.type !== "wallet") return null;
    var chains = (ctx.data.chains && ctx.data.chains.length) ? ctx.data.chains : guessChains(ctx.value);
    var box = make("div", "te-section");
    box.appendChild(make("h3", "te-section__title", "On-chain info"));
    if (!chains.length) {
      box.appendChild(make("p", "te-empty", "No chain is known for this wallet."));
      return box;
    }
    var stored = ctx.data.onchain || {};
    chains.forEach(function (chain) {
      var name = providerFor(chain);
      var wrap = make("div", "te-chain");
      var head = make("div", "te-chain__head");
      head.appendChild(make("strong", null, CHAIN_LABELS[chain] || chain));
      wrap.appendChild(head);
      if (!name) {
        wrap.appendChild(make("p", "te-note", "No on-chain provider covers this chain yet."));
        box.appendChild(wrap);
        return;
      }
      var provider = PROVIDERS[name];
      var status = make("p", "te-note");
      status.setAttribute("aria-live", "polite");
      var button = make("button", "btn btn--small", stored[chain] ? "Refresh" : "Look up on " + provider.label);
      button.type = "button";
      button.addEventListener("click", function () { lookup(ctx.id, chain, ctx.value, status, button); });
      head.appendChild(button);
      if (provider.needsKey && !keys[name]) {
        status.textContent = "Needs your " + provider.label + " key (Keys button in the top bar).";
      }
      if (stored[chain]) wrap.appendChild(renderSummary(stored[chain].summary, stored[chain].cached_at));
      wrap.appendChild(status);
      box.appendChild(wrap);
    });
    return box;
  }

  /* -------------------------------------------------------------- keys panel */

  function keyState() {
    Object.keys(PROVIDERS).forEach(function (name) {
      var badge = el.badges[name];
      var isSet = !!keys[name];
      badge.textContent = isSet ? "Set for this session" : (PROVIDERS[name].needsKey ? "Not set" : "Not set (optional)");
      badge.className = "te-keys__badge" + (isSet ? " is-set" : "");
    });
  }

  function saveKeys() {
    Object.keys(PROVIDERS).forEach(function (name) {
      var input = el.inputs[name];
      var value = (input.value || "").trim();
      if (value) keys[name] = value;
      input.value = "";
    });
    keyState();
    core.rerenderDetail();
    core.setStatus("Provider keys saved in memory for this page session.", "ok");
  }

  function clearKeys() {
    Object.keys(PROVIDERS).forEach(function (name) {
      keys[name] = "";
      el.inputs[name].value = "";
    });
    keyState();
    core.rerenderDetail();
    core.setStatus("Provider keys cleared.");
  }

  function openKeys() {
    el.panel.hidden = false;
    el.inputs.etherscan.focus();
  }

  function closeKeys() {
    el.panel.hidden = true;
    Object.keys(el.inputs).forEach(function (name) { el.inputs[name].value = ""; });
  }

  function init() {
    core = window.TitanEye && window.TitanEye.core;
    el.panel = document.getElementById("te-keys");
    if (!core || !el.panel) return false;
    el.inputs = {
      etherscan: document.getElementById("te-key-etherscan"),
      blockchain: document.getElementById("te-key-blockchain"),
      tronscan: document.getElementById("te-key-tronscan")
    };
    el.badges = {
      etherscan: document.getElementById("te-key-etherscan-state"),
      blockchain: document.getElementById("te-key-blockchain-state"),
      tronscan: document.getElementById("te-key-tronscan-state")
    };
    document.getElementById("te-keys-open").addEventListener("click", openKeys);
    document.getElementById("te-keys-close").addEventListener("click", closeKeys);
    document.getElementById("te-keys-save").addEventListener("click", function () {
      saveKeys();
      closeKeys();
    });
    document.getElementById("te-keys-clear").addEventListener("click", clearKeys);
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && !el.panel.hidden) {
        event.stopImmediatePropagation();
        closeKeys();
      }
    }, true);
    core.addDetailSection(detailSection);
    keyState();
    return true;
  }

  return { init: init };
})();
