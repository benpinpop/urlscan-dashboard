/* Query-bar autocomplete for urlscan search fields.
 *
 * The field list comes from /api/query-terms (database/query_terms.csv), once
 * per page load. Suggestions are for field names only: the token under the
 * caret is completed to "field:" and nothing is ever submitted from here, so
 * app.js keeps owning search, Enter-to-submit and pivots.
 *
 * CSV text is treated as untrusted: every node is built with createElement and
 * filled with textContent.
 */

(function () {
  "use strict";

  /* Whole words that are query syntax, not field names. */
  var OPERATORS = { AND: true, OR: true, NOT: true, "&&": true, "||": true };
  /* A partial field name: page.domain, domain.keyword, _exists_. */
  var FIELD_SHAPE = /^[A-Za-z_][A-Za-z0-9_.]*$/;
  /* Characters that end a token when scanning forward from the caret. */
  var TOKEN_END = /[\s():"\[\]{}\/]/;
  var MAX_RESULTS = 40;

  /* ------------------------------------------------------------ pure logic */

  /* The field-name token around the caret, or null when the caret is
   * somewhere a field name does not belong: after a field's colon, inside a
   * quoted phrase, a /regex/ or a [range]. Whitespace, brackets and the
   * AND / OR / NOT operators separate tokens; a leading - + or ! is kept out
   * of the replacement. After "_exists_:" the value is itself a field name,
   * so that position completes too (without adding a colon). */
  function tokenAt(value, caret) {
    var start = 0;
    var colon = -1;
    var inQuote = false;
    var inRegex = false;
    var inRange = false;
    var i, ch;

    for (i = 0; i < caret; i++) {
      ch = value.charAt(i);
      if (inQuote || inRegex) {
        if (ch === "\\") { i++; continue; }
        if (inQuote && ch === "\"") inQuote = false;
        else if (inRegex && ch === "/") inRegex = false;
        continue;
      }
      if (inRange) {
        if (ch === "]" || ch === "}") inRange = false;
        continue;
      }
      if (ch === "\\") { i++; continue; }
      if (ch === "\"") inQuote = true;
      else if (ch === "/" && (i === start || i === colon + 1)) inRegex = true;
      else if (ch === "[" || ch === "{") inRange = true;
      else if (/[\s()]/.test(ch)) { start = i + 1; colon = -1; }
      else if (ch === ":" && colon < 0) colon = i;
    }
    if (inQuote || inRegex || inRange || i > caret) return null;

    var lead = start;
    while (lead < caret && "-+!".indexOf(value.charAt(lead)) >= 0) lead++;

    var mode = "field";
    if (colon >= 0) {
      if (value.slice(lead, colon) !== "_exists_") return null;
      mode = "exists";
      lead = colon + 1;
    }

    var end = caret;
    while (end < value.length && !TOKEN_END.test(value.charAt(end))) end++;

    var word = value.slice(lead, end);
    var text = value.slice(lead, caret);
    if (!text || OPERATORS[word] || !FIELD_SHAPE.test(word)) return null;

    return {
      start: lead,
      end: end,
      text: text,
      mode: mode,
      /* "dom|ain:x" — the colon is already there, so only the name changes. */
      hasColon: mode === "field" && value.charAt(end) === ":"
    };
  }

  /* Matches for a partial field name, best first: prefix of the whole name,
   * then prefix of a dotted segment ("keyword" -> domain.keyword), then any
   * substring. Ties go free before Pro, then alphabetical. */
  function rank(terms, text) {
    var q = String(text || "").toLowerCase();
    var out = [];
    if (!q) return out;
    terms.forEach(function (term) {
      var field = term.field.toLowerCase();
      var tier = -1;
      var at = field.indexOf(q);
      if (at === 0) {
        tier = 0;
      } else if (field.indexOf("." + q) >= 0) {
        tier = 1;
        at = field.indexOf("." + q) + 1;
      } else if (at > 0) {
        tier = 2;
      }
      if (tier >= 0) out.push({ term: term, tier: tier, at: at, length: q.length });
    });
    out.sort(function (a, b) {
      var pro = (a.term.plan === "pro") - (b.term.plan === "pro");
      var fa = a.term.field.toLowerCase();
      var fb = b.term.field.toLowerCase();
      return a.tier - b.tier || pro || (fa < fb ? -1 : fa > fb ? 1 : 0);
    });
    return out.slice(0, MAX_RESULTS);
  }

  /* The input's new value and caret after accepting a term. Only the token
   * changes; everything before and after it is kept byte for byte. */
  function complete(value, token, term, useExample) {
    var insert;
    var after = value.slice(token.end);
    var extra = 0;

    if (useExample && term.example && token.mode === "field" && !token.hasColon) {
      insert = term.example;
    } else if (token.mode === "exists") {
      insert = term.field;
    } else if (token.hasColon) {
      insert = term.field;
      extra = 1;                       /* land after the colon that is already there */
    } else {
      insert = term.field + ":";
    }

    var before = value.slice(0, token.start);
    return { value: before + insert + after, caret: before.length + insert.length + extra };
  }

  var api = { tokenAt: tokenAt, rank: rank, complete: complete };
  if (typeof module === "object" && module.exports) module.exports = api;
  if (typeof document === "undefined") return;

  /* ------------------------------------------------------------ the widget */

  var input = document.getElementById("query");
  var box = document.getElementById("query-box");
  var popup = document.getElementById("query-suggest");
  var list = document.getElementById("query-suggest-list");
  var status = document.getElementById("query-suggest-status");
  if (!input || !box || !popup || !list) return;

  var terms = [];
  var matches = [];
  var active = -1;
  var token = null;
  var announceTimer = null;

  input.setAttribute("role", "combobox");
  input.setAttribute("aria-autocomplete", "list");
  input.setAttribute("aria-expanded", "false");
  input.setAttribute("aria-controls", list.id);

  function make(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  /* Polite and debounced, so a screen reader hears the count once typing
   * pauses rather than on every keystroke. */
  function announce(message) {
    if (!status) return;
    window.clearTimeout(announceTimer);
    if (!message) { status.textContent = ""; return; }
    announceTimer = window.setTimeout(function () { status.textContent = message; }, 350);
  }

  function buildOption(match, index) {
    var term = match.term;
    var item = make("li", "qac__option");
    item.id = "query-suggest-" + index;
    item.setAttribute("role", "option");
    item.setAttribute("aria-selected", "false");
    item.dataset.index = String(index);

    var head = make("div", "qac__head");
    var name = make("span", "qac__field mono");
    name.appendChild(document.createTextNode(term.field.slice(0, match.at)));
    name.appendChild(make("strong", "qac__match", term.field.slice(match.at, match.at + match.length)));
    name.appendChild(document.createTextNode(term.field.slice(match.at + match.length)));
    head.appendChild(name);

    var tags = make("span", "qac__tags");
    if (term.type) tags.appendChild(make("span", "qac__type", term.type));
    if (term.regex === "true") {
      var regex = make("span", "qac__regex", "regex");
      regex.title = "Accepts /regex/ values";
      tags.appendChild(regex);
    }
    if (term.plan === "pro") {
      var pro = make("span", "pro-badge", "PRO");
      pro.title = "Requires a urlscan Pro plan";
      tags.appendChild(pro);
    }
    head.appendChild(tags);
    item.appendChild(head);

    if (term.description) item.appendChild(make("p", "qac__desc", term.description));
    if (term.example) {
      var example = make("p", "qac__example");
      example.appendChild(make("code", "qac__code", term.example));
      example.appendChild(make("span", "qac__use", "Insert example"));
      item.appendChild(example);
    }
    return item;
  }

  function close() {
    token = null;
    if (popup.hidden) return;
    popup.hidden = true;
    list.textContent = "";
    matches = [];
    active = -1;
    input.setAttribute("aria-expanded", "false");
    input.removeAttribute("aria-activedescendant");
    announce("");
  }

  function show(found, ranked) {
    token = found;
    matches = ranked;
    active = -1;
    list.textContent = "";
    ranked.forEach(function (match, index) { list.appendChild(buildOption(match, index)); });
    list.scrollTop = 0;
    popup.hidden = false;
    input.setAttribute("aria-expanded", "true");
    input.removeAttribute("aria-activedescendant");
    announce(ranked.length + (ranked.length === 1 ? " suggestion" : " suggestions"));
  }

  /* Re-read the caret. Typing may open the list; caret moves (arrows, clicks)
   * only refresh or close a list that is already open, and programmatic value
   * changes (pivots, examples) fire no event at all, so they never open it. */
  function update(mayOpen) {
    if (!terms.length || document.activeElement !== input) { close(); return; }
    var caret = input.selectionStart;
    if (caret === null || caret !== input.selectionEnd) { close(); return; }
    var found = tokenAt(input.value, caret);
    if (!found || (popup.hidden && !mayOpen)) { close(); return; }
    var ranked = rank(terms, found.text);
    if (!ranked.length) { close(); return; }
    show(found, ranked);
  }

  function setActive(index) {
    var options = list.children;
    if (active >= 0 && options[active]) {
      options[active].classList.remove("is-active");
      options[active].setAttribute("aria-selected", "false");
    }
    active = index;
    if (active < 0 || !options[active]) {
      input.removeAttribute("aria-activedescendant");
      return;
    }
    options[active].classList.add("is-active");
    options[active].setAttribute("aria-selected", "true");
    input.setAttribute("aria-activedescendant", options[active].id);
    options[active].scrollIntoView({ block: "nearest" });
  }

  function move(step) {
    var count = matches.length;
    if (!count) return;
    if (active < 0) setActive(step > 0 ? 0 : count - 1);
    else setActive((active + step + count) % count);
  }

  function accept(index, useExample) {
    var match = matches[index];
    /* Re-read the token: the value may have been changed under an open list. */
    var current = tokenAt(input.value, input.selectionStart);
    if (!match || !token || !current) { close(); return; }
    var result = complete(input.value, current, match.term, useExample);
    close();
    input.value = result.value;
    input.focus();
    input.setSelectionRange(result.caret, result.caret);
  }

  function consume(event) {
    event.preventDefault();
    event.stopPropagation();
  }

  /* Capture phase on the wrapper, so this runs before app.js's Enter handler
   * on the input itself and can keep a highlighted Enter from searching. */
  box.addEventListener("keydown", function (event) {
    if (event.target !== input || event.isComposing) return;
    var open = !popup.hidden && matches.length > 0;

    switch (event.key) {
      case "ArrowDown":
      case "ArrowUp":
        if (!open) {
          if (event.key === "ArrowDown" && !event.altKey) {
            update(true);
            if (!popup.hidden) consume(event);
          }
          return;
        }
        consume(event);
        move(event.key === "ArrowDown" ? 1 : -1);
        return;
      case "Enter":
        if (open && active >= 0) {
          consume(event);
          accept(active, event.shiftKey);
          return;
        }
        close();                       /* plain Enter: app.js runs the search */
        return;
      case "Tab":
        if (open && !event.shiftKey) {
          consume(event);
          accept(active >= 0 ? active : 0, false);
        }
        return;
      case "Escape":
        /* type="search" would also clear the box on Escape; only the list closes. */
        if (open) consume(event);
        close();
        return;
    }
  }, true);

  input.addEventListener("input", function () { update(true); });
  input.addEventListener("click", function () { update(false); });
  input.addEventListener("keyup", function (event) {
    if (/^(ArrowLeft|ArrowRight|Home|End)$/.test(event.key)) update(false);
  });
  input.addEventListener("blur", close);

  /* mousedown, not click, and no default: the input keeps focus, so blur does
   * not close the list before the choice lands. */
  popup.addEventListener("mousedown", function (event) {
    event.preventDefault();
    if (event.button !== 0) return;
    var option = event.target.closest ? event.target.closest(".qac__option") : null;
    if (!option || !list.contains(option)) return;
    accept(Number(option.dataset.index), !!event.target.closest(".qac__example"));
  });

  fetch("/api/query-terms", { headers: { Accept: "application/json" }, cache: "no-store" })
    .then(function (response) { return response.json(); })
    .then(function (body) {
      if (!body || !body.ok || !Array.isArray(body.terms)) return;
      terms = body.terms.filter(function (term) {
        return term && typeof term.field === "string" && term.field;
      });
    })
    .catch(function () { /* no list, no suggestions; the search box works as before */ });
})();
