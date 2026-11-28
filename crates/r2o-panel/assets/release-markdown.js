/* Markdown описаний выпуска. Marked разбирает синтаксис, а разрешённые элементы
   создаются через DOM API: исходный HTML никогда не вставляется в документ. */
(function (root) {
  "use strict";

  var commonjs = typeof module !== "undefined" && module.exports;
  var marked = commonjs ? require("./marked.js") : root.marked;
  var previous = new WeakMap();
  // Подписанные заметки ограничены 4096 байтами. Запас допускает старые локальные
  // снимки; большие и чрезмерно вложенные документы остаются целиком читаемыми.
  var MAX_SOURCE = 16 * 1024;
  var MAX_DEPTH = 32;
  var MAX_TOKENS = 4096;
  var MAX_NODES = 4096;
  var MAX_ENTITIES = 256;
  var ENTITY = /&(?:#[0-9]{1,8}|#[xX][0-9a-fA-F]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});/g;

  function string(value) { return value === undefined || value === null ? "" : String(value); }
  function list(value) { return Array.isArray(value) ? value : []; }

  function entities(value, context) {
    return string(value).replace(ENTITY, function (entity) {
      if (context.entities.has(entity)) return context.entities.get(entity);
      var decoded = entity;
      if (context.entityParser) {
        // Only one strictly matched reference reaches the inert parser. It
        // contains no '<', '>', quotes, attributes, or arbitrary source markup.
        var parsed = context.entityParser.parseFromString("<span>" + entity + "</span>", "text/html");
        decoded = parsed.body.textContent;
      }
      if (context.entities.size < MAX_ENTITIES) context.entities.set(entity, decoded);
      return decoded;
    });
  }

  function element(context, name, className) {
    if (++context.nodes > MAX_NODES) throw new Error("Markdown node budget");
    var node = context.doc.createElement(name);
    if (className) node.className = className;
    return node;
  }

  function text(parent, value, context, literal) {
    if (++context.nodes > MAX_NODES) throw new Error("Markdown node budget");
    parent.appendChild(context.doc.createTextNode(literal ? string(value) : entities(value, context)));
  }

  function safeUrl(value, context, image) {
    var href = entities(value, context);
    // Relative paths would target the router, including its control API.
    // Reject controls before URL normalisation can silently remove them.
    if (/[\u0000-\u0020\u007f]/.test(href) ||
        !(image ? /^https?:\/\//i : /^(?:https?:\/\/|mailto:)/i).test(href)) return null;
    try {
      var url = new context.URL(href);
      if ((url.protocol === "http:" || url.protocol === "https:") && url.hostname) return url.href;
      if (!image && url.protocol === "mailto:") return url.href;
    } catch (_) {}
    return null;
  }

  function headingShift(tokens) {
    var stack = [{ tokens: tokens, depth: 0 }], count = 0, first = 6;
    while (stack.length) {
      var frame = stack.pop();
      if (frame.depth > MAX_DEPTH) throw new Error("Markdown depth budget");
      for (var token of frame.tokens) {
        if (++count > MAX_TOKENS || !token || typeof token !== "object") throw new Error("Markdown token budget");
        if (token.type === "heading") first = Math.min(first, Number(token.depth) || 6);
        var children = [];
        if (Array.isArray(token.tokens)) children.push(token.tokens);
        if (Array.isArray(token.items)) children.push(token.items);
        if (Array.isArray(token.header)) children.push(token.header);
        if (Array.isArray(token.rows)) children.push.apply(children, token.rows);
        for (var child of children) stack.push({ tokens: child, depth: frame.depth + 1 });
      }
    }
    // The surrounding Updates screen owns h1/h2. Keep the note's hierarchy
    // while placing its first heading no higher than h3.
    return Math.max(0, 3 - first);
  }

  function inlineLabel(token, parent, context, depth, insideLink) {
    if (Array.isArray(token.tokens) && token.tokens.length) {
      renderTokens(token.tokens, parent, context, depth + 1, true, insideLink);
    } else {
      text(parent, token.text, context, false);
    }
  }

  function renderTable(token, parent, context, depth) {
    var wrapper = element(context, "div", "release-markdown-table");
    var table = element(context, "table");
    var head = element(context, "thead"), body = element(context, "tbody");
    function row(cells, header) {
      var tr = element(context, "tr");
      list(cells).forEach(function (cell, index) {
        var td = element(context, header ? "th" : "td");
        var align = cell.align || list(token.align)[index];
        if (["left", "center", "right"].indexOf(align) !== -1) td.setAttribute("data-align", align);
        if (header) td.setAttribute("scope", "col");
        inlineLabel(cell, td, context, depth, false);
        tr.appendChild(td);
      });
      return tr;
    }
    head.appendChild(row(token.header, true));
    list(token.rows).forEach(function (cells) { body.appendChild(row(cells, false)); });
    table.appendChild(head);
    table.appendChild(body);
    wrapper.appendChild(table);
    parent.appendChild(wrapper);
  }

  function renderTokens(tokens, parent, context, depth, inline, insideLink) {
    if (depth > MAX_DEPTH) throw new Error("Markdown depth budget");
    for (var token of list(tokens)) {
      var node, destination, name;
      switch (token.type) {
        case "space":
        case "def":
          break;
        case "heading":
          name = "h" + Math.min(6, Math.max(3, (Number(token.depth) || 3) + context.headingShift));
          node = element(context, name);
          inlineLabel(token, node, context, depth, false);
          parent.appendChild(node);
          break;
        case "paragraph":
          node = element(context, "p");
          inlineLabel(token, node, context, depth, insideLink);
          parent.appendChild(node);
          break;
        case "text":
          if (Array.isArray(token.tokens)) {
            node = inline ? parent : element(context, "p");
            inlineLabel(token, node, context, depth, insideLink);
            if (node !== parent) parent.appendChild(node);
          } else {
            text(parent, token.text, context, false);
          }
          break;
        case "escape":
          text(parent, token.text, context, true);
          break;
        case "strong":
        case "em":
        case "del":
          node = element(context, token.type);
          inlineLabel(token, node, context, depth, insideLink);
          parent.appendChild(node);
          break;
        case "codespan":
          node = element(context, "code");
          text(node, token.text, context, true);
          parent.appendChild(node);
          break;
        case "code":
          node = element(context, "pre");
          var code = element(context, "code");
          var language = string(token.lang).split(/\s/, 1)[0];
          if (/^[A-Za-z0-9_-]{1,32}$/.test(language)) code.className = "language-" + language;
          text(code, token.text, context, true);
          node.appendChild(code);
          parent.appendChild(node);
          break;
        case "br":
        case "hr":
          parent.appendChild(element(context, token.type));
          break;
        case "blockquote":
          node = element(context, "blockquote");
          renderTokens(token.tokens, node, context, depth + 1, false, false);
          parent.appendChild(node);
          break;
        case "list":
          node = element(context, token.ordered ? "ol" : "ul");
          if (token.ordered && Number.isSafeInteger(token.start) && token.start >= 0) node.start = token.start;
          if (list(token.items).some(function (item) { return item.task; })) node.className = "task-list";
          for (var item of list(token.items)) {
            var li = element(context, "li", item.task ? "task-list-item" : "");
            renderTokens(item.tokens, li, context, depth + 1, !item.loose, false);
            node.appendChild(li);
          }
          parent.appendChild(node);
          break;
        case "checkbox":
          node = element(context, "input");
          node.type = "checkbox";
          node.disabled = true;
          node.checked = !!token.checked;
          node.setAttribute("aria-label", token.checked ? "Выполнено" : "Не выполнено");
          parent.appendChild(node);
          break;
        case "table":
          renderTable(token, parent, context, depth + 1);
          break;
        case "link":
        case "image":
          destination = insideLink ? null : safeUrl(token.href, context, token.type === "image");
          node = destination ? element(context, "a") : parent;
          if (destination) {
            node.href = destination;
            if (/^https?:/i.test(destination)) node.target = "_blank";
            node.rel = "noopener noreferrer";
            if (token.title) node.title = entities(token.title, context);
          }
          if (token.type === "image" && !string(token.text)) text(node, "Изображение", context, true);
          else inlineLabel(token, node, context, depth, insideLink || !!destination);
          if (node !== parent) parent.appendChild(node);
          break;
        case "html":
          if (token.block) {
            node = element(context, "pre", "release-markdown-html");
            text(node, token.raw || token.text, context, true);
            parent.appendChild(node);
          } else {
            text(parent, token.raw || token.text, context, true);
          }
          break;
        default:
          // A newer parser token must not silently drop part of the release.
          throw new Error("Unsupported Markdown token");
      }
    }
  }

  function render(target, source) {
    if (!target || !target.ownerDocument) return false;
    source = string(source);
    var last = previous.get(target);
    if (last && last.source === source && last.parser === marked) return false;
    var doc = target.ownerDocument, view = doc.defaultView || root;
    var fragment = doc.createDocumentFragment();
    try {
      if (!marked || typeof marked.lexer !== "function" || source.length > MAX_SOURCE ||
          /^(?: {0,3}>[ \t]*){33}/m.test(source)) throw new Error("Markdown input budget");
      var tokens = marked.lexer(source, { gfm: true, breaks: false, pedantic: false });
      var Parser = view.DOMParser || root.DOMParser;
      var context = {
        doc: doc, URL: view.URL || root.URL, nodes: 0,
        entityParser: Parser ? new Parser() : null, entities: new Map(),
        headingShift: headingShift(tokens)
      };
      renderTokens(tokens, fragment, context, 0, false, false);
    } catch (_) {
      fragment = doc.createDocumentFragment();
      var plain = doc.createElement("pre");
      plain.className = "release-markdown-plain";
      plain.textContent = source;
      fragment.appendChild(plain);
    }
    target.classList.add("release-markdown");
    target.replaceChildren(fragment);
    previous.set(target, { source: source, parser: marked });
    return true;
  }

  var api = { render: render };
  if (commonjs) module.exports = api;
  else root.R2oMarkdown = api;
})(typeof window !== "undefined" ? window : globalThis);
