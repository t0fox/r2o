/* R2O — схема Telegram-прокси.
   Новый приборный холст: клиент, ядро r2o, четыре маршрута и пять DC.
   Показывает не только движение пакетов, но и состояние каждого маршрута,
   подтверждение, паузы, этапы отказа и активность дата-центров. */
(function (global) {
  "use strict";

  var WIDTH = 960;
  var HEIGHT = 310;
  var MOBILE_WIDTH = 360;
  var MOBILE_HEIGHT = 692;
  var MOBILE_BREAKPOINT = 680;
  var MONO = '"IBM Plex Mono", monospace';
  var SANS = '"Manrope", sans-serif';
  var ROW_TITLE = '700 12px ' + SANS;
  var ROW_DETAIL = '10px ' + MONO;
  var SVG_NS = "http://www.w3.org/2000/svg";
  var MAX_PARTICLES = 24;
  var ROUTE_TONES = ["direct", "worker", "cloudflare", "tcp"];

  var ROUTES = [
    { transport: "direct_wss", label: "Прямой WSS" },
    { transport: "cloudflare_worker", label: "Cloudflare Worker" },
    { transport: "cloudflare_proxy", label: "Прокси Cloudflare" },
    { transport: "tcp_passthrough", label: "Прямой TCP · диагностика" }
  ];
  var TRANSPORT_TO_LANE = {
    direct_wss: 0,
    cloudflare_worker: 1,
    cloudflare_proxy: 2,
    tcp_passthrough: 3,
    tcp_fallback: 3
  };
  var ROUTE_WORDS = {
    idle: "резерв",
    connecting: "подключение",
    connected: "готов",
    selected: "активен",
    race: "гонка",
    cooldown: "пауза",
    failed: "отказ",
    cancelled: "отменён",
    skipped: "пропуск"
  };
  var FAILURE_STAGES = { 1: "DNS", 2: "TCP", 3: "TLS", 4: "WebSocket", 5: "MTProto", 6: "маршрут", 7: "WSS" };
  var GATES = ["DNS", "TCP", "TLS", "WS", "MTP"];

  var DESKTOP = {
    client: { x: 16, y: 12, w: 150, h: 286 },
    core: { x: 196, y: 12, w: 160, h: 286 },
    routes: { x: 386, y: 12, w: 342, h: 286 },
    dcs: { x: 758, y: 12, w: 186, h: 286 },
    routeRows: { x: 398, y: 54, w: 318, h: 50, gap: 8 },
    dcRows: { x: 770, y: 54, w: 162, h: 39, gap: 9 }
  };
  var MOBILE = {
    client: { x: 20, y: 12, w: 320, h: 102 },
    core: { x: 20, y: 128, w: 320, h: 148 },
    routes: { x: 20, y: 290, w: 320, h: 230 },
    dcs: { x: 20, y: 534, w: 320, h: 146 },
    routeRows: { x: 32, y: 328, w: 296, h: 42, gap: 4 },
    dcRows: { x: 32, y: 570, w: 296, h: 18, gap: 3 }
  };

  function clamp(value, min, max) { return Math.max(min, Math.min(max, value)); }

  function plural(n, one, few, many) {
    var m10 = n % 10, m100 = n % 100;
    if (m10 === 1 && m100 !== 11) return one;
    if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return few;
    return many;
  }

  function cssColor(value, fallback) {
    if (!value) return fallback;
    var text = String(value).trim();
    var hex = text.match(/^#([0-9a-f]{3,8})$/i);
    if (hex) {
      var raw = hex[1];
      if (raw.length === 3) raw = raw.split("").map(function (part) { return part + part; }).join("");
      if (raw.length >= 6) {
        return [parseInt(raw.slice(0, 2), 16), parseInt(raw.slice(2, 4), 16), parseInt(raw.slice(4, 6), 16)];
      }
    }
    var rgb = text.match(/rgba?\(([^)]+)\)/i);
    if (rgb) {
      var parts = rgb[1].split(/[,\s/]+/).filter(Boolean).map(Number);
      if (parts.length >= 3 && parts.every(function (part) { return Number.isFinite(part); })) {
        return [parts[0], parts[1], parts[2]];
      }
    }
    return fallback;
  }

  function rgba(color, alpha) {
    return "rgba(" + (color[0] | 0) + "," + (color[1] | 0) + "," + (color[2] | 0) + "," + clamp(alpha, 0, 1) + ")";
  }

  function laneIndex(transport) {
    return Object.prototype.hasOwnProperty.call(TRANSPORT_TO_LANE, transport) ? TRANSPORT_TO_LANE[transport] : -1;
  }

  function dcNumber(dc) {
    var number = Number(dc);
    if (number === 203) return 2;
    return Number.isInteger(number) && number >= 1 && number <= 5 ? number : null;
  }

  function latencyText(ms) {
    var value = Number(ms);
    if (!Number.isFinite(value) || value < 0) return "—";
    return Math.round(value) + " мс";
  }

  function makeAtmosphere(doc, canAnimate) {
    var field = doc.createElement("pre");
    field.className = "tg-flow-signal-field";
    field.setAttribute("aria-hidden", "true");
    var symbols = "01·+";
    field.textContent = Array.from({ length: 40 }, function (_, y) {
      return Array.from({ length: 170 }, function (_, x) {
        return Math.sin(x * 0.29 - y * 0.64) + Math.sin(x * 0.16 + y * 0.35) > 0.7
          ? symbols[(x * 3 + y) % symbols.length] : " ";
      }).join("");
    }).join("\n");

    var orb = doc.createElementNS(SVG_NS, "svg");
    orb.classList.add("tg-flow-orb");
    orb.setAttribute("viewBox", "0 0 100 100");
    orb.setAttribute("aria-hidden", "true");
    orb.innerHTML = [
      '<rect class="tg-orbit-hit" width="100" height="100"/>',
      '<circle class="tg-orbit-fill" cx="50" cy="50" r="43"/>',
      '<g class="tg-orbit-edge"/>',
      '<g class="tg-orbit-turn tg-orbit-cross"/>',
      '<g class="tg-orbit-turn"/>',
      '<g class="tg-orbit-label"/>'
    ].join("");

    var layers = Array.from(orb.querySelectorAll("g"), function (node) { return { node: node, pixels: [] }; });
    var point = null, frame = 0, last = 0, index = 0;

    function addPixel(layer, x, y, size) {
      var node = doc.createElementNS(SVG_NS, "rect");
      node.setAttribute("x", (x - size / 2).toFixed(2));
      node.setAttribute("y", (y - size / 2).toFixed(2));
      node.setAttribute("width", size);
      node.setAttribute("height", size);
      node.setAttribute("rx", Math.min(size / 2, 0.4));
      layer.node.append(node);
      var angle = ++index * 2.39996;
      layer.pixels.push({ node: node, x: x, y: y, dx: 0, dy: 0, vx: Math.cos(angle), vy: Math.sin(angle),
        spread: 38 + 28 * (0.5 + 0.5 * Math.cos(angle * 1.31)) });
    }

    function ring(layer, rx, ry, tilt, count, size) {
      var cos = Math.cos(tilt), sin = Math.sin(tilt);
      for (var i = 0; i < count; i += 1) {
        var angle = i / count * 2 * Math.PI;
        var x = rx * Math.cos(angle), y = ry * Math.sin(angle);
        addPixel(layer, 50 + x * cos - y * sin, 50 + x * sin + y * cos, i % 6 === 0 ? size * 1.65 : size);
      }
    }

    ring(layers[0], 40, 40, 0, 50, 1.2);
    ring(layers[1], 37, 17, 0.49, 29, 1.55);
    ring(layers[2], 38, 18, -0.54, 34, 1.65);
    ["11110/10001/10001/11110/10100/10010/10001",
      "01110/10001/00001/00010/00100/01000/11111",
      "01110/10001/10001/10001/10001/10001/01110"].forEach(function (glyph, letter) {
      glyph.split("/").forEach(function (row, y) {
        for (var x = 0; x < row.length; x += 1) {
          if (row[x] === "1") addPixel(layers[3], 50 + (letter * 6 + x - 8) * 2.18, 50 + (y - 3) * 2.18, 2.0);
        }
      });
    });

    function paint(now) {
      frame = 0;
      var viewport = orb.getScreenCTM();
      if (!viewport) return;
      var inverse = viewport.inverse();
      var cursor = point && point.matrixTransform(inverse);
      var ease = 1 - Math.exp(-Math.min(32, last ? now - last : 16) / (cursor ? 58 : 115));
      last = now;
      var moving = false;
      // Координаты орбит читаются до записи смещений частиц для текущего кадра.
      var matrices = layers.map(function (layer) { return inverse.multiply(layer.node.getScreenCTM()); });
      layers.forEach(function (layer, i) {
        var matrix = matrices[i];
        layer.pixels.forEach(function (pixel) {
          var tx = 0, ty = 0;
          if (cursor) {
            var x = matrix.a * pixel.x + matrix.c * pixel.y + matrix.e - cursor.x;
            var y = matrix.b * pixel.x + matrix.d * pixel.y + matrix.f - cursor.y;
            var distance = Math.hypot(x, y);
            var force = pixel.spread * Math.max(0, 1 - distance / 105);
            var bias = 0.34 / Math.max(1, distance);
            tx = force * (pixel.vx + bias * x);
            ty = force * (pixel.vy + bias * y) * 0.82;
          }
          pixel.dx += (tx - pixel.dx) * ease;
          pixel.dy += (ty - pixel.dy) * ease;
          if (!cursor && Math.hypot(pixel.dx, pixel.dy) < 0.12) {
            pixel.dx = pixel.dy = 0;
            pixel.node.removeAttribute("transform");
            return;
          }
          // Смещение остаётся в координатах ядра, пока орбита под частицей вращается.
          var localX = matrix.a * pixel.dx + matrix.b * pixel.dy;
          var localY = matrix.c * pixel.dx + matrix.d * pixel.dy;
          pixel.node.setAttribute("transform", "translate(" + localX.toFixed(2) + " " + localY.toFixed(2) + ")");
          moving = true;
        });
      });
      if (cursor || moving) frame = window.requestAnimationFrame(paint);
      else last = 0;
    }

    orb.addEventListener("pointermove", function (event) {
      if (event.pointerType !== "mouse" || !canAnimate()) return;
      point = new DOMPoint(event.clientX, event.clientY);
      if (!frame) frame = window.requestAnimationFrame(paint);
    }, { passive: true });
    orb.addEventListener("pointerleave", function () { point = null; });

    function resetOrb() {
      if (!frame) return;
      window.cancelAnimationFrame(frame);
      frame = last = 0;
      point = null;
      for (var layer of layers) for (var pixel of layer.pixels) {
        pixel.dx = pixel.dy = 0;
        pixel.node.removeAttribute("transform");
      }
    }

    return { field: field, orb: orb, resetOrb: resetOrb };
  }

  function mountTelegramFlow(canvas) {
    var api = global.R2oTelegramFlow;
    if (!api) throw new Error("Данные анимации Telegram не загружены");
    var context = canvas.getContext("2d");
    if (!context) throw new Error("Canvas 2D недоступен для схемы Telegram");
    var links = canvas.ownerDocument.createElementNS(SVG_NS, "svg");
    links.classList.add("tg-flow-links");
    links.setAttribute("aria-hidden", "true");
    var overlay = canvas.ownerDocument.createElement("canvas");
    overlay.className = "tg-flow-particles";
    overlay.setAttribute("aria-hidden", "true");
    var brush = overlay.getContext("2d");
    canvas.before(links);
    canvas.after(overlay);
    var stage = canvas.parentElement;
    var atmosphere = makeAtmosphere(canvas.ownerDocument, canAnimate);
    stage.prepend(atmosphere.field);
    canvas.after(atmosphere.orb);
    var reduce = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : null;

    var fallback = {
      line: [46, 58, 68],
      text: [231, 236, 239],
      muted: [148, 163, 173],
      accent: [127, 208, 212],
      failure: [185, 106, 106],
      warning: [198, 155, 89],
      confirmed: [127, 175, 132],
      background: [14, 19, 23],
      surface: [17, 22, 26],
      direct: [185, 138, 82],
      worker: [183, 161, 236],
      cloudflare: [127, 208, 212],
      tcp: [111, 152, 184]
    };
    var palette = Object.assign({}, fallback);
    var paletteReady = false;

    var view = api.summarizeTelegramFlow(null, "");
    var snapshot = null;
    var paths = new Map();
    var flows = new Map();
    var previousBySession = new Map();
    var particles = [];
    var layout = DESKTOP;
    var lastDraw = 0;
    var frameId = 0;
    var inView = true;
    var destroyed = false;
    var layoutMobile = false;
    var maxConnections = 0;

    function prefersReduced() { return !!(reduce && reduce.matches); }

    function refreshPalette() {
      if (!canvas.isConnected) return;
      var style = window.getComputedStyle(canvas);
      palette.line = cssColor(style.getPropertyValue("--tg-flow-line"), fallback.line);
      palette.text = cssColor(style.getPropertyValue("--tg-flow-text"), fallback.text);
      palette.muted = cssColor(style.getPropertyValue("--tg-flow-muted"), fallback.muted);
      palette.accent = cssColor(style.getPropertyValue("--tg-flow-accent"), fallback.accent);
      palette.failure = cssColor(style.getPropertyValue("--tg-flow-failure"), fallback.failure);
      palette.warning = cssColor(style.getPropertyValue("--tg-flow-warning"), fallback.warning);
      palette.confirmed = cssColor(style.getPropertyValue("--tg-flow-confirmed"), fallback.confirmed);
      palette.background = cssColor(style.getPropertyValue("--tg-flow-background"), fallback.background);
      palette.surface = cssColor(style.getPropertyValue("--tg-flow-surface"), fallback.surface);
      for (var tone of ROUTE_TONES) {
        palette[tone] = cssColor(style.getPropertyValue("--tg-flow-" + tone), fallback[tone]);
      }
      paletteReady = true;
    }

    function routeStatus(lane) {
      if (lane.counts && lane.counts.selected) return lane.confirmed ? "selected" : "connecting";
      if (lane.counts && (lane.counts.race || lane.counts.connecting)) return lane.counts.race ? "race" : "connecting";
      if (lane.counts && lane.counts.failed) return "failed";
      if (lane.cooldownCount) return "cooldown";
      if (lane.counts && lane.counts.cancelled) return "cancelled";
      if (lane.counts && lane.counts.skipped) return "skipped";
      return "idle";
    }

    function countsText(lane) {
      var parts = [];
      var counts = lane.counts || {};
      ["connecting", "race", "failed", "cancelled", "skipped"].forEach(function (state) {
        if (Number(counts[state]) > 0) parts.push(ROUTE_WORDS[state] + " " + counts[state]);
      });
      var unconfirmed = (Number(counts.selected) || 0) - (Number(lane.confirmed) || 0);
      if (unconfirmed > 0) parts.push("ожидается ответ " + unconfirmed);
      if (lane.cooldownCount) parts.push("пауза " + lane.cooldownCount);
      if (lane.confirmed) parts.push("подтверждено " + lane.confirmed);
      return parts.length ? parts.join(" · ") : "нет сессий";
    }

    function roundRect(x, y, w, h, r) {
      var radius = Math.min(r, w / 2, h / 2);
      context.beginPath();
      context.moveTo(x + radius, y);
      context.arcTo(x + w, y, x + w, y + h, radius);
      context.arcTo(x + w, y + h, x, y + h, radius);
      context.arcTo(x, y + h, x, y, radius);
      context.arcTo(x, y, x + w, y, radius);
      context.closePath();
    }

    function panel(x, y, w, h, tint) {
      roundRect(x, y, w, h, 9);
      context.fillStyle = rgba(palette.surface, 0.94);
      context.fill();
      if (tint) {
        context.fillStyle = rgba(tint, 0.055);
        context.fill();
      }
      context.strokeStyle = rgba(tint || palette.line, tint ? 0.42 : 0.9);
      context.lineWidth = 1;
      context.stroke();
    }

    function line(x1, y1, x2, y2, color, alpha, width, dash, dashOffset) {
      context.save();
      context.beginPath();
      context.moveTo(x1, y1);
      context.lineTo(x2, y2);
      context.strokeStyle = rgba(color, alpha);
      context.lineWidth = width || 1;
      context.setLineDash(dash || []);
      context.lineDashOffset = dashOffset || 0;
      context.stroke();
      context.restore();
    }

    function text(value, x, y, font, color, align, baseline) {
      context.save();
      context.font = font;
      context.fillStyle = rgba(color, 1);
      context.textAlign = align || "left";
      context.textBaseline = baseline || "middle";
      context.fillText(String(value), x, y);
      context.restore();
    }

    function measure(value, font) {
      context.save();
      context.font = font;
      var width = context.measureText(String(value)).width;
      context.restore();
      return width;
    }

    function fitText(value, maxWidth, font) {
      var out = String(value == null ? "" : value);
      if (measure(out, font) <= maxWidth) return out;
      while (out.length > 1 && measure(out + "…", font) > maxWidth) out = out.slice(0, -1);
      return out + "…";
    }

    function mono(value, x, y, size, color, align) {
      text(value, x, y, (size || 9) + 'px "IBM Plex Mono", monospace', color, align || "left", "middle");
    }

    function label(value, x, y, color) {
      text(value, x, y, '700 12px ' + SANS, color || palette.text);
    }

    function chip(value, x, y, color, options) {
      options = options || {};
      var pad = options.pad || 7;
      var font = options.font || '10px "IBM Plex Mono", monospace';
      context.save();
      context.font = font;
      var width = Math.ceil(context.measureText(String(value)).width) + pad * 2;
      var height = options.height || 18;
      roundRect(x, y - height / 2, width, height, 4);
      context.fillStyle = rgba(color, options.fill === false ? 0.06 : 0.12);
      context.fill();
      context.strokeStyle = rgba(color, 0.38);
      context.lineWidth = 1;
      context.stroke();
      context.fillStyle = rgba(color, 0.94);
      context.textAlign = "left";
      context.textBaseline = "middle";
      context.fillText(String(value), x + pad, y + 0.5);
      context.restore();
      return width;
    }

    function dot(x, y, color, radius) {
      context.save();
      context.beginPath();
      context.arc(x, y, radius || 2.2, 0, Math.PI * 2);
      context.fillStyle = rgba(color, 0.95);
      context.fill();
      context.restore();
    }

    function chipRight(value, rightX, y, color, options) {
      options = options || {};
      var pad = options.pad || 7;
      var font = options.font || '10px "IBM Plex Mono", monospace';
      var width = Math.ceil(measure(value, font)) + pad * 2;
      chip(value, rightX - width, y, color, options);
      return width;
    }

    function rowTop(index) { return layout.routeRows.y + index * (layout.routeRows.h + layout.routeRows.gap); }
    function rowCenter(index) { return rowTop(index) + layout.routeRows.h / 2; }
    function dcTop(index) { return layout.dcRows.y + index * (layout.dcRows.h + layout.dcRows.gap); }
    function dcCenter(index) { return dcTop(index) + layout.dcRows.h / 2; }

    function dcPath(dc, lane) {
      var route = layout.routeRows, node = layout.dcRows;
      var x = route.x + route.w;
      var bus = layoutMobile ? MOBILE_WIDTH - 10 : layout.dcs.x - 15;
      var end = layoutMobile ? node.x + node.w : node.x;
      return [[x, rowCenter(lane)], [bus, rowCenter(lane)], [bus, dcCenter(dc - 1)], [end, dcCenter(dc - 1)]];
    }

    function ingressPath() {
      var client = layout.client, core = layout.core;
      if (layoutMobile) return verticalLink(client, core);
      var y = core.y + 100;
      return [[client.x + client.w, y], [core.x, y]];
    }

    function verticalLink(first, second) {
      var x = first.x + first.w / 2;
      return [[x, first.y + first.h], [x, second.y]];
    }

    function card(box, title, tint) {
      panel(box.x, box.y, box.w, box.h, tint);
      label(title, box.x + 14, box.y + 20);
    }

    function drawClient() {
      var box = layout.client;
      var count = String(view.activeConnections);
      var font = '650 32px "Unbounded", ' + SANS;
      card(box, "Клиент");
      text(fitText(count, layoutMobile ? 82 : box.w - 28, font), box.x + 14, box.y + 60, font, palette.text);
      text("Активные", box.x + 14, box.y + 84, '10px ' + SANS, palette.muted);

      var values = [
        ["Принято", view.acceptedConnections],
        ["Медиа", view.mediaSessions],
        ["Сессии", String(view.sessions.length) + (view.truncated ? "+" : "")]
      ];
      if (maxConnections > 0) values.push(["Лимит", maxConnections]);
      if (layoutMobile) {
        var columns = (box.w - 118) / 2;
        values.forEach(function (item, index) {
          var x = box.x + 104 + index % 2 * columns;
          var y = box.y + 48 + Math.floor(index / 2) * 27;
          text(item[0], x, y, '10px ' + SANS, palette.muted);
          mono(fitText(item[1], columns - 12, '11px ' + MONO), x + columns - 11, y, 11, palette.text, "right");
        });
      } else {
        line(box.x + 14, box.y + 108, box.x + box.w - 14, box.y + 108, palette.line, 0.9, 1);
        values.forEach(function (item, index) {
          var y = box.y + 135 + index * 33;
          text(item[0], box.x + 14, y, '11px ' + SANS, palette.muted);
          mono(fitText(item[1], 64, '11px ' + MONO), box.x + box.w - 14, y, 11, palette.text, "right");
        });
      }
    }

    function drawGates(box, y) {
      var passed = 0, failed = 0;
      view.lanes.forEach(function (lane) {
        passed = Math.max(passed, Number(lane.passedGate) || 0);
        if (routeStatus(lane) === "failed") failed = Math.max(failed, Number(lane.failureStage) || 0);
      });
      var width = (box.w - 28 - 4 * 4) / 5;
      GATES.forEach(function (gate, index) {
        var x = box.x + 14 + index * (width + 4);
        var color = failed === index + 1 ? palette.failure : passed > index ? palette.accent : palette.muted;
        roundRect(x, y, width, 18, 4);
        context.fillStyle = rgba(color, passed > index ? 0.12 : 0.045);
        context.fill();
        context.strokeStyle = rgba(color, 0.32);
        context.lineWidth = 1;
        context.stroke();
        mono(gate, x + width / 2, y + 9, layoutMobile ? 9 : 8, color, "center");
      });
    }

    function drawCore() {
      var box = layout.core;
      var active = stage.dataset.motion === "confirmed";
      var tone = active ? palette.accent : view.activeConnections ? palette.warning : palette.muted;
      card(box, "Прокси R2O", active ? palette.accent : null);
      var x = layoutMobile ? box.x + 76 : box.x + 14;
      var y = box.y + (layoutMobile ? 56 : 158);
      var width = box.x + box.w - 14 - x;
      text(fitText(view.transportLabel || "Маршрут не выбран", width, ROW_TITLE), x, y, ROW_TITLE, palette.text);
      text(fitText(view.dcLabel || "DC неизвестен", width, ROW_DETAIL), x, y + 20, ROW_DETAIL, palette.muted);
      var gateY = box.y + (layoutMobile ? 113 : 232);
      label("Этапы соединения", box.x + 14, gateY - 11);
      drawGates(box, gateY);
      if (!layoutMobile) {
        var dc = dcNumber(snapshot && snapshot.last_success_dc);
        var detail = dc ? "DC" + dc + " · " + latencyText(snapshot.last_success_latency_ms) : "Ответов пока нет";
        mono(detail, box.x + 14, box.y + 267, 10, dc ? palette.confirmed : palette.muted);
      }
    }

    function drawRouteRow(lane, index) {
      var rows = layout.routeRows;
      var x = rows.x, top = rowTop(index), w = rows.w, h = rows.h;
      var status = routeStatus(lane);
      var routeTone = palette[ROUTE_TONES[index]];
      var color = status === "failed" ? palette.failure : routeTone;
      var active = status === "selected" || status === "connecting" || status === "race";
      roundRect(x, top, w, h, 7);
      context.fillStyle = rgba(status === "idle" ? palette.background : color, status === "idle" ? 0.6 : 0.07);
      context.fill();
      context.strokeStyle = rgba(status === "idle" ? palette.line : color, status === "idle" ? 0.74 : 0.34);
      context.lineWidth = 1;
      context.stroke();

      dot(x + 13, top + 13, routeTone, 2.2);
      var state = ROUTE_WORDS[status] || status;
      if (status === "failed" && Number(lane.failureStage)) state += " · " + (FAILURE_STAGES[Number(lane.failureStage)] || "сбой");
      if (status === "cooldown" && Number(lane.cooldownRemainingMs)) state += " · " + Math.ceil(Number(lane.cooldownRemainingMs) / 1000) + " с";
      var chipFont = '9px ' + MONO;
      var badgeWidth = chipRight(fitText(state, 105, chipFont), x + w - 8, top + 13, color,
        { font: chipFont, height: 16, pad: 5 });
      text(fitText(lane.label, w - badgeWidth - 40, ROW_TITLE),
        x + 23, top + 13, ROW_TITLE, status === "idle" ? palette.muted : palette.text);
      text(fitText(countsText(lane), w - 35, ROW_DETAIL), x + 23, top + (layoutMobile ? 26 : 29), ROW_DETAIL, palette.muted);

      var rail = top + h - 5;
      line(x + 10, rail, x + w - 10, rail, active ? color : palette.line, active ? 0.52 : 0.55, 1);
      if (Number(lane.cooldownRemainingMs) > 0 && Number(view.cooldownDurationMs) > 0) {
        var ratio = clamp(Number(lane.cooldownRemainingMs) / Number(view.cooldownDurationMs), 0, 1);
        line(x + 10, rail, x + 10 + (w - 20) * ratio, rail, palette.warning, 0.85, 2);
      }
    }

    function drawRoutes() {
      card(layout.routes, "Маршруты");
      view.lanes.forEach(drawRouteRow);
    }

    function drawDcs() {
      card(layout.dcs, "Telegram DC");
      var rows = layout.dcRows;
      for (var index = 0; index < 5; index += 1) {
        var activity = (view.dcActivity || [])[index] || {};
        var active = Number(activity.active) || 0;
        var media = Number(activity.media) || 0;
        var confirmed = Number(activity.confirmed) || 0;
        var color = confirmed ? palette.confirmed : active ? palette.accent : palette.muted;
        var top = dcTop(index);
        roundRect(rows.x, top, rows.w, rows.h, 6);
        context.fillStyle = rgba(active ? color : palette.background, active ? 0.1 : 0.58);
        context.fill();
        context.strokeStyle = rgba(active ? color : palette.line, active ? 0.42 : 0.64);
        context.lineWidth = 1;
        context.stroke();

        var y = top + (layoutMobile ? 9 : 13);
        dot(rows.x + 10, y, color, active ? 2.4 : 2);
        mono("DC" + (index + 1), rows.x + 19, y, 11, active ? palette.text : palette.muted);
        var detail = active
          ? (media ? "Медиа " + media : "") + (confirmed ? (media ? " · " : "") + "✓ " + confirmed : "")
          : "Нет сессий";
        if (layoutMobile) {
          var summary = active ? active + " " + plural(active, "сессия", "сессии", "сессий") + (detail ? " · " + detail : "") : detail;
          text(fitText(summary, rows.w - 70, ROW_DETAIL), rows.x + rows.w - 10, y, ROW_DETAIL, color, "right");
        } else {
          mono(active || "—", rows.x + rows.w - 10, y, 12, color, "right");
          if (detail) text(fitText(detail, rows.w - 28, ROW_DETAIL), rows.x + 19, top + 29, ROW_DETAIL, palette.muted);
        }
      }
    }

    function dispatchPath(index) {
      var core = layout.core;
      var y = core.y + (layoutMobile ? core.h - 17 : 100);
      var x = layoutMobile ? core.x : core.x + core.w;
      var bus = x + (layoutMobile ? -10 : 15);
      return [[x, y], [bus, y], [bus, rowCenter(index)], [layout.routeRows.x, rowCenter(index)]];
    }

    function syncPaths() {
      var wanted = new Map();
      var inbound = "idle";
      for (var flow of flows.values()) {
        var active = flow.state === "confirmed";
        var dispatch = "dispatch-" + flow.lane;
        if (active || !wanted.has(dispatch)) wanted.set(dispatch, [dispatchPath(flow.lane), flow.state, flow.lane]);
        if (active) {
          inbound = "confirmed";
          wanted.set("out-" + flow.lane + "-" + flow.dc, [dcPath(flow.dc, flow.lane), "confirmed", flow.lane]);
        } else if (inbound === "idle") {
          inbound = "discovery";
        }
      }
      view.lanes.forEach(function (lane, index) {
        var key = "dispatch-" + index;
        if (view.state !== "stale" && routeStatus(lane) === "failed" &&
            Number.isFinite(lane.failureAgeMs) && lane.failureAgeMs < 1000 && !wanted.has(key)) {
          wanted.set(key, [dispatchPath(index), "failed", index]);
        }
      });
      wanted.set("in", [ingressPath(), inbound]);

      for (var [key, entry] of paths) {
        if (!wanted.has(key)) {
          entry.node.remove();
          paths.delete(key);
        }
      }
      for (var [key, [points, state, lane]] of wanted) {
        var d = points.map(function (point, index) {
          return (index ? "L" : "M") + point[0] + " " + point[1];
        }).join(" ");
        var entry = paths.get(key);
        if (!entry) {
          var node = canvas.ownerDocument.createElementNS(SVG_NS, "path");
          node.dataset.link = key;
          if (lane !== undefined) node.style.setProperty("--tg-link-color", "var(--tg-flow-" + ROUTE_TONES[lane] + ")");
          links.appendChild(node);
          entry = { node: node, d: "", length: 0 };
          paths.set(key, entry);
        }
        if (entry.d !== d || !entry.length) {
          entry.node.setAttribute("d", d);
          entry.d = d;
          entry.length = entry.node.getTotalLength();
        }
        if (entry.node.dataset.state !== state) entry.node.dataset.state = state;
      }
    }

    function draw() {
      if (!paletteReady) refreshPalette();
      var width = layoutMobile ? MOBILE_WIDTH : WIDTH;
      var height = layoutMobile ? MOBILE_HEIGHT : HEIGHT;
      context.setTransform(canvas.width / width, 0, 0, canvas.height / height, 0, 0);
      context.clearRect(0, 0, width, height);
      drawClient();
      drawCore();
      drawRoutes();
      drawDcs();
    }

    function canAnimate() {
      return !!brush && !destroyed && inView && !document.hidden && !prefersReduced();
    }

    function emit(pulses, now) {
      if (!canAnimate()) return;
      var batches = [];
      for (var [key, counts] of pulses) {
        var flow = flows.get(key);
        if (!flow) continue;
        var segments = [paths.get("in"), paths.get("dispatch-" + flow.lane)];
        if (flow.dc) segments.push(paths.get("out-" + flow.lane + "-" + flow.dc));
        if (segments.some(function (path) { return !path || !path.length; })) continue;
        var speed = flow.state === "confirmed" ? 0.31 : 0.18;
        if (counts[0]) batches.push({ key: key, segments: segments, speed: speed, count: counts[0], reverse: false });
        if (counts[1]) batches.push({ key: key, segments: segments.slice().reverse(), speed: speed, count: counts[1], reverse: true });
      }
      for (var i = 0; i < 4; i += 1) {
        for (var batch of batches) {
          if (particles.length >= MAX_PARTICLES) return;
          if (i >= batch.count) continue;
          var tone = ROUTE_TONES[Math.floor(Math.random() * ROUTE_TONES.length)];
          var size = 0.65 + Math.random() * 0.85;
          particles.push({ key: batch.key, segments: batch.segments, reverse: batch.reverse,
            speed: batch.speed, tone: tone, size: size, start: now + i * 85 });
        }
      }
    }

    function clearParticles() {
      if (brush) brush.clearRect(0, 0, layoutMobile ? MOBILE_WIDTH : WIDTH, layoutMobile ? MOBILE_HEIGHT : HEIGHT);
    }

    function paintParticles(now) {
      clearParticles();
      for (var i = particles.length - 1; i >= 0; i -= 1) {
        var particle = particles[i];
        var flow = flows.get(particle.key);
        if (!flow) {
          particles.splice(i, 1);
          continue;
        }
        var distance = (now - particle.start) * particle.speed;
        if (distance < 0) continue;
        var path = null;
        for (var segment of particle.segments) {
          if (distance <= segment.length) {
            path = segment;
            break;
          }
          distance -= segment.length;
        }
        if (!path) {
          particles.splice(i, 1);
          continue;
        }
        var active = flow.state === "confirmed";
        var head = path.node.getPointAtLength(particle.reverse ? path.length - distance : distance);
        var color = palette[particle.tone];
        var size = particle.size;
        brush.beginPath();
        var tail = (active ? 15 : 8) * size;
        for (var j = 0; j <= 3; j += 1) {
          var offset = Math.max(0, distance - tail + j * tail / 3);
          var point = path.node.getPointAtLength(particle.reverse ? path.length - offset : offset);
          if (!j) brush.moveTo(point.x, point.y); else brush.lineTo(point.x, point.y);
        }
        brush.lineCap = "round";
        brush.strokeStyle = rgba(color, active ? 0.2 : 0.09);
        brush.lineWidth = (active ? 5 : 3) * size;
        brush.stroke();
        brush.strokeStyle = rgba(color, active ? 0.91 : 0.42);
        brush.lineWidth = (active ? 1.8 : 1) * size;
        brush.stroke();
        brush.fillStyle = rgba(color, active ? 1 : 0.54);
        brush.beginPath();
        brush.arc(head.x, head.y, (active ? 2.15 : 1.25) * size, 0, Math.PI * 2);
        brush.fill();
      }
    }

    function updateAccessibility() {
      var routes = view.lanes.map(function (lane) {
        return lane.label + " — " + (ROUTE_WORDS[routeStatus(lane)] || routeStatus(lane)) + ", " + countsText(lane);
      }).join("; ");
      var dcs = (view.dcActivity || []).map(function (activity, index) {
        return "DC" + (index + 1) + ": активных " + activity.active + ", медиа " + activity.media + ", подтверждено " + activity.confirmed;
      }).join("; ");
      var race = view.hedged.length ? " Параллельная гонка: победил " + view.hedged[0].winner + "." : "";
      var truncated = view.truncated ? " Показана ограниченная выборка сессий." : "";
      canvas.setAttribute("aria-label", "Схема Telegram-прокси: " + view.caption + ". Маршруты: " + routes + ". " + dcs + "." + race + truncated);
      canvas.dataset.state = view.state;
    }

    function resize() {
      if (destroyed) return;
      var width = canvas.getBoundingClientRect().width;
      if (!width) return;
      var compact = width < MOBILE_BREAKPOINT;
      var changed = layoutMobile !== compact;
      layoutMobile = compact;
      layout = compact ? MOBILE : DESKTOP;
      canvas.classList.toggle("is-compact", compact);
      var height = canvas.getBoundingClientRect().height;
      var pixelRatio = Math.min(2.5, Math.max(1, window.devicePixelRatio || 1));
      var backingWidth = Math.round(width * pixelRatio), backingHeight = Math.round(height * pixelRatio);
      if (!changed && canvas.width === backingWidth && canvas.height === backingHeight && overlay.width === Math.round(width)) return;
      stopLoop();
      canvas.width = backingWidth;
      canvas.height = backingHeight;
      overlay.width = Math.round(width);
      overlay.height = Math.round(height);
      var logicalWidth = compact ? MOBILE_WIDTH : WIDTH;
      var logicalHeight = compact ? MOBILE_HEIGHT : HEIGHT;
      var core = layout.core;
      atmosphere.orb.style.left = (core.x + (compact ? 39 : core.w / 2)) / logicalWidth * 100 + "%";
      atmosphere.orb.style.top = (core.y + (compact ? 66 : 100)) / logicalHeight * 100 + "%";
      atmosphere.orb.style.width = (compact ? 52 : 78) / logicalWidth * 100 + "%";
      links.setAttribute("viewBox", "0 0 " + logicalWidth + " " + logicalHeight);
      links.setAttribute("preserveAspectRatio", "none");
      if (brush) brush.setTransform(overlay.width / logicalWidth, 0, 0, overlay.height / logicalHeight, 0, 0);
      syncPaths();
      draw();
    }

    function updateFrame(now) {
      frameId = 0;
      if (!canAnimate()) { stopLoop(); return; }
      if (now - lastDraw >= 33) {
        paintParticles(now);
        lastDraw = now;
      }
      startLoop();
    }

    function startLoop() {
      if (!frameId && particles.length && canAnimate()) frameId = window.requestAnimationFrame(updateFrame);
    }

    function stopLoop() {
      if (frameId) window.cancelAnimationFrame(frameId);
      frameId = 0;
      particles.length = 0;
      clearParticles();
    }

    var cardKey = "";

    function update(nextSnapshot, error) {
      if (destroyed) return null;
      if (snapshot?.process_started_at !== nextSnapshot?.process_started_at) previousBySession.clear();
      snapshot = nextSnapshot || null;
      maxConnections = Number(snapshot && snapshot.max_connections) || 0;
      view = api.summarizeTelegramFlow(snapshot, error || undefined);
      var before = flows;
      flows = api.motionRoutes(view);
      var state = "idle";
      for (var flow of flows.values()) {
        state = flow.state;
        if (state === "confirmed") break;
      }
      stage.dataset.motion = state;
      syncPaths();
      particles = particles.filter(function (particle) { return flows.has(particle.key); });
      clearParticles();
      var sessions = view.state === "stale" ? [] : view.sessions;
      var traffic = api.collectConfirmedTrafficDeltas(previousBySession, sessions);
      var now = performance.now();
      var pulses = new Map();
      for (var [key, flow] of flows) {
        if (!before.has(key)) pulses.set(key, flow.dc ? [1, 1] : [1, 0]);
      }
      for (var delta of traffic) {
        var key = delta.laneIndex + ":" + delta.dc;
        var count = delta.bytes >= 4096 ? 4 : delta.bytes >= 512 ? 3 : 1;
        var counts = pulses.get(key) || [0, 0];
        var direction = delta.direction === "response" ? 1 : 0;
        counts[direction] = Math.max(counts[direction], count);
        pulses.set(key, counts);
      }
      emit(pulses, now);
      startLoop();

      var key = JSON.stringify([view.state, view.caption, view.activeConnections, view.acceptedConnections,
        view.mediaSessions, view.sessions.length, view.truncated, view.dcLabel, view.transportLabel,
        view.lanes, view.dcActivity, maxConnections, snapshot?.last_success_dc, snapshot?.last_success_latency_ms]);
      if (key !== cardKey) {
        cardKey = key;
        updateAccessibility();
        draw();
      }
      return view;
    }

    function syncVisibility() {
      var paused = !canAnimate();
      stage.classList.toggle("is-motion-paused", paused);
      if (paused) atmosphere.resetOrb();
    }

    function onVisibility() {
      syncVisibility();
      if (document.hidden) stopLoop();
    }

    function onIntersection(entries) {
      inView = Boolean(entries[0] && entries[0].isIntersecting);
      syncVisibility();
      if (!inView) stopLoop();
    }

    function onMotionChange() {
      syncVisibility();
      if (prefersReduced()) stopLoop();
    }

    var resizeObserver = typeof window.ResizeObserver === "function" ? new window.ResizeObserver(resize) : null;
    var intersectionObserver = typeof window.IntersectionObserver === "function"
      ? new window.IntersectionObserver(onIntersection, { rootMargin: "80px" }) : null;
    var themeObserver = typeof window.MutationObserver === "function"
      ? new window.MutationObserver(function () { refreshPalette(); draw(); }) : null;

    refreshPalette();
    resize();
    resizeObserver && resizeObserver.observe(canvas);
    intersectionObserver && intersectionObserver.observe(canvas);
    themeObserver && themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    window.addEventListener("resize", resize, { passive: true });
    document.addEventListener("visibilitychange", onVisibility);
    if (reduce && reduce.addEventListener) reduce.addEventListener("change", onMotionChange);
    syncVisibility();

    return {
      update: update,
      attach: function () {
        if (destroyed || !canvas.isConnected) return;
        refreshPalette();
        resize();
      },
      destroy: function () {
        if (destroyed) return;
        destroyed = true;
        stopLoop();
        atmosphere.resetOrb();
        resizeObserver && resizeObserver.disconnect();
        intersectionObserver && intersectionObserver.disconnect();
        themeObserver && themeObserver.disconnect();
        window.removeEventListener("resize", resize);
        document.removeEventListener("visibilitychange", onVisibility);
        if (reduce && reduce.removeEventListener) reduce.removeEventListener("change", onMotionChange);
        previousBySession.clear();
        paths.clear();
        flows.clear();
        links.remove();
        overlay.remove();
        atmosphere.field.remove();
        atmosphere.orb.remove();
        stage.classList.remove("is-motion-paused");
        delete stage.dataset.motion;
      }
    };
  }

  global.R2oTelegramPrototype = { mountTelegramFlow: mountTelegramFlow };
})(typeof window !== "undefined" ? window : globalThis);
