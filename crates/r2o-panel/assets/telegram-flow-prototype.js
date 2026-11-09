/* R2O — схема Telegram-туннеля.
   Новый приборный холст: клиент, ядро r2o, четыре маршрута и пять DC.
   Показывает не только движение пакетов, но и состояние каждого маршрута,
   подтверждение, паузы, этапы отказа и активность дата-центров. */
(function (global) {
  "use strict";

  var WIDTH = 960;
  var HEIGHT = 420;
  var MOBILE_WIDTH = 420;
  var MOBILE_HEIGHT = 740;

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
  var STATE_WORDS = {
    active: "АКТИВЕН",
    mixed: "СМЕШАННЫЙ",
    race: "ГОНКА",
    searching: "ПОДБОР",
    unavailable: "НЕДОСТУПЕН",
    idle: "ПРОСТОЙ",
    cooling: "ПАУЗА",
    stale: "УСТАРЕЛ"
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

  var CLIENT = { x: 24, y: 76, w: 150, h: 264 };
  var CORE = { x: 196, y: 76, w: 164, h: 264 };
  var ROUTES_BOARD = { x: 384, y: 76, w: 344, h: 264 };
  var DC_BOARD = { x: 752, y: 76, w: 184, h: 264 };
  var ROW_X = ROUTES_BOARD.x + 14;
  var ROW_W = ROUTES_BOARD.w - 28;
  var ROW_H = 50;
  var ROW_GAP = 7;
  var ROW_TOP = ROUTES_BOARD.y + 30;
  var DC_X = DC_BOARD.x + 12;
  var DC_W = DC_BOARD.w - 24;
  var DC_H = 40;
  var DC_GAP = 6;
  var DC_TOP = DC_BOARD.y + 30;

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

  function shortText(text, max) {
    text = String(text || "");
    return text.length > max ? text.slice(0, Math.max(1, max - 1)) + "…" : text;
  }

  function ageText(ms) {
    var value = Number(ms);
    if (!Number.isFinite(value) || value < 0) return "";
    if (value < 1000) return "только что";
    var seconds = Math.floor(value / 1000);
    if (seconds < 60) return seconds + " с назад";
    var minutes = Math.floor(seconds / 60);
    if (minutes < 60) return minutes + " мин назад";
    var hours = Math.floor(minutes / 60);
    return hours + " ч назад";
  }

  function latencyText(ms) {
    var value = Number(ms);
    if (!Number.isFinite(value) || value < 0) return "—";
    return Math.round(value) + " мс";
  }

  function mountTelegramFlow(canvas) {
    var api = global.R2oTelegramFlow;
    if (!api) throw new Error("Данные анимации Telegram не загружены");
    var context = canvas.getContext("2d", { alpha: false });
    if (!context) throw new Error("Canvas 2D недоступен для схемы Telegram");
    var root = canvas.closest(".tg-flow");
    var reduce = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : null;

    var fallback = {
      line: [46, 58, 68],
      text: [231, 236, 239],
      muted: [116, 129, 139],
      accent: [127, 208, 212],
      accent2: [215, 164, 91],
      failure: [185, 106, 106],
      warning: [198, 155, 89],
      confirmed: [127, 175, 132],
      background: [14, 19, 23],
      surface: [17, 22, 26],
      direct: [185, 138, 82],
      cloudflare: [127, 208, 212],
      tcp: [111, 152, 184]
    };
    var palette = Object.assign({}, fallback);
    var paletteReady = false;

    var view = api.summarizeTelegramFlow(null, "");
    var snapshot = null;
    var particles = [];
    var pulses = [];
    var sparks = [];
    var dcPulse = [0, 0, 0, 0, 0];
    var corePulse = 0;
    var statePulse = 0;
    var lastSpawn = 0;
    var lastFrame = 0;
    var lastDraw = 0;
    var clock = 0;
    var frameId = 0;
    var inView = true;
    var destroyed = false;
    var pixelRatio = 1;
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
      palette.accent2 = cssColor(style.getPropertyValue("--tg-flow-accent-2"), fallback.accent2);
      palette.failure = cssColor(style.getPropertyValue("--tg-flow-failure"), fallback.failure);
      palette.warning = cssColor(style.getPropertyValue("--tg-flow-warning"), fallback.warning);
      palette.confirmed = cssColor(style.getPropertyValue("--tg-flow-confirmed"), fallback.confirmed);
      palette.background = cssColor(style.getPropertyValue("--tg-flow-background"), fallback.background);
      palette.surface = cssColor(style.getPropertyValue("--tg-flow-surface"), fallback.surface);
      palette.direct = cssColor(style.getPropertyValue("--tg-flow-direct"), fallback.direct);
      palette.cloudflare = cssColor(style.getPropertyValue("--tg-flow-cloudflare"), fallback.cloudflare);
      palette.tcp = cssColor(style.getPropertyValue("--tg-flow-tcp"), fallback.tcp);
      paletteReady = true;
    }

    function laneColor(lane) {
      if (!lane) return palette.muted;
      if (lane.status === "failed") return palette.failure;
      if (lane.status === "cooldown" || lane.status === "cancelled" || lane.status === "skipped") return palette.warning;
      if (lane.status === "connecting" || lane.status === "race") return palette.warning;
      if (lane.status === "selected" || lane.status === "connected") return lane.index === 3 ? palette.tcp : lane.index === 0 ? palette.direct : palette.cloudflare;
      return palette.muted;
    }

    function routeStatus(lane) {
      if (lane.counts && lane.counts.selected) return "selected";
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
      ["selected", "connecting", "race", "failed", "cancelled", "skipped"].forEach(function (state) {
        if (Number(counts[state]) > 0) parts.push(ROUTE_WORDS[state] + " " + counts[state]);
      });
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
      context.fillStyle = rgba(tint || palette.surface, tint ? 0.16 : 0.72);
      context.fill();
      context.strokeStyle = rgba(palette.line, 0.72);
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

    function path(points, color, alpha, width, dash) {
      if (!points.length) return;
      context.save();
      context.beginPath();
      context.moveTo(points[0][0], points[0][1]);
      for (var i = 1; i < points.length; i++) context.lineTo(points[i][0], points[i][1]);
      context.strokeStyle = rgba(color, alpha);
      context.lineWidth = width || 1;
      context.lineJoin = "round";
      context.lineCap = "round";
      context.setLineDash(dash || []);
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
      text(value, x, y, '600 8px "IBM Plex Mono", monospace', color || palette.muted, "left", "middle");
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

    function rowTop(index) { return ROW_TOP + index * (ROW_H + ROW_GAP); }
    function rowCenter(index) { return rowTop(index) + ROW_H / 2; }
    function dcTop(index) { return DC_TOP + index * (DC_H + DC_GAP); }
    function dcCenter(index) { return dcTop(index) + DC_H / 2; }

    function pointOnPolyline(points, progress) {
      var lengths = [];
      var total = 0;
      for (var i = 1; i < points.length; i++) {
        var segment = Math.hypot(points[i][0] - points[i - 1][0], points[i][1] - points[i - 1][1]);
        lengths.push(segment);
        total += segment;
      }
      var target = clamp(progress, 0, 1) * total;
      for (var j = 0; j < lengths.length; j++) {
        if (target <= lengths[j] || j === lengths.length - 1) {
          var ratio = lengths[j] ? target / lengths[j] : 0;
          return [
            points[j][0] + (points[j + 1][0] - points[j][0]) * ratio,
            points[j][1] + (points[j + 1][1] - points[j][1]) * ratio
          ];
        }
        target -= lengths[j];
      }
      return points[points.length - 1];
    }

    function dcPath(session, lane) {
      var dc = dcNumber(session && session.dc);
      var laneIndexValue = lane >= 0 ? lane : laneIndex(session && session.selected_transport);
      if (dc === null || laneIndexValue < 0) return null;
      return [
        [ROW_X + ROW_W, rowCenter(laneIndexValue)],
        [ROW_X + ROW_W + 16, rowCenter(laneIndexValue)],
        [ROW_X + ROW_W + 16, dcCenter(dc - 1)],
        [DC_X, dcCenter(dc - 1)]
      ];
    }

    function drawBackground(width, height) {
      var gradient = context.createLinearGradient(0, 0, 0, height);
      gradient.addColorStop(0, rgba(palette.background, 1));
      gradient.addColorStop(1, rgba(palette.surface, 1));
      context.fillStyle = gradient;
      context.fillRect(0, 0, width, height);
      context.save();
      context.globalAlpha = 0.32;
      for (var x = 0; x <= width; x += 24) line(x, 0, x, height, palette.line, 0.08, 1);
      for (var y = 0; y <= height; y += 24) line(0, y, width, y, palette.line, 0.08, 1);
      context.restore();
      line(0, 60, width, 60, palette.line, 0.5, 1);
    }

    function drawStatus(width) {
      var state = STATE_WORDS[view.state] || String(view.state || "—").toUpperCase();
      var stateColor = view.state === "active" || view.state === "mixed" ? palette.accent2
        : view.state === "unavailable" || view.state === "stale" ? palette.failure
          : view.state === "idle" ? palette.muted : palette.warning;
      var stats = view.activeConnections + " активных · " + view.acceptedConnections + " принято" +
        (view.mediaSessions ? " · медиа " + view.mediaSessions : "");
      var statsFont = '9px "IBM Plex Mono", monospace';
      var statsWidth = Math.min(300, measure(fitText(stats, 300, statsFont), statsFont) + 18);
      var statsLeft = width - 24 - statsWidth;
      var x = 24;
      x += chip(state, x, 28, stateColor, { font: '600 10px "IBM Plex Mono", monospace' }) + 9;
      if (view.transportLabel) {
        var transport = fitText(view.transportLabel, Math.max(80, statsLeft - x - 16), statsFont);
        mono(transport, x, 28, 9, palette.text);
        x += measure(transport, statsFont) + 14;
      }
      if (view.dcLabel) {
        var dcFont = '10px "IBM Plex Mono", monospace';
        var dcText = fitText(view.dcLabel, 150, dcFont);
        var dcWidth = measure(dcText, dcFont) + 14;
        if (x + dcWidth < statsLeft - 8) chip(dcText, x, 28, palette.accent, { font: dcFont });
      }
      mono(fitText(stats, 300, statsFont), width - 24, 28, 9, palette.muted, "right");
    }

    function drawClient() {
      panel(CLIENT.x, CLIENT.y, CLIENT.w, CLIENT.h, palette.surface);
      label("КЛИЕНТ", CLIENT.x + 14, CLIENT.y + 17);
      label("MTProto", CLIENT.x + CLIENT.w - 14, CLIENT.y + 17);
      // Устройство: экран и нижняя полоса.
      var dx = CLIENT.x + 14, dy = CLIENT.y + 38;
      roundRect(dx, dy, 30, 46, 5);
      context.strokeStyle = rgba(palette.accent, 0.7);
      context.lineWidth = 1.3;
      context.stroke();
      roundRect(dx + 5, dy + 6, 20, 28, 2);
      context.strokeStyle = rgba(palette.accent, 0.28);
      context.stroke();
      dot(dx + 15, dy + 41, palette.accent, 1.2);
      // Главное число активных сессий.
      text(view.activeConnections, CLIENT.x + 76, CLIENT.y + 56, '600 32px "Unbounded", sans-serif', palette.text, "left", "middle");
      mono("активных", CLIENT.x + 78, CLIENT.y + 78, 9, palette.muted);
      line(CLIENT.x + 14, CLIENT.y + 96, CLIENT.x + CLIENT.w - 14, CLIENT.y + 96, palette.line, 0.7, 1);
      var rows = [
        ["принято", String(view.acceptedConnections)],
        ["медиа", String(view.mediaSessions)],
        ["сессий", String(view.sessions.length) + (view.truncated ? "+" : "")]
      ];
      rows.forEach(function (item, index) {
        var y = CLIENT.y + 116 + index * 24;
        mono(item[0], CLIENT.x + 14, y, 9, palette.muted);
        mono(item[1], CLIENT.x + CLIENT.w - 14, y, 10, palette.text, "right");
      });
      if (maxConnections > 0) {
        line(CLIENT.x + 14, CLIENT.y + 188, CLIENT.x + CLIENT.w - 14, CLIENT.y + 188, palette.line, 0.5, 1);
        mono("лимит", CLIENT.x + 14, CLIENT.y + 204, 9, palette.muted);
        mono(maxConnections, CLIENT.x + CLIENT.w - 14, CLIENT.y + 204, 10, palette.text, "right");
      }
      var portY = CLIENT.y + CLIENT.h - 18;
      line(CLIENT.x + 14, portY - 18, CLIENT.x + CLIENT.w - 14, portY - 18, palette.line, 0.5, 1);
      mono("TCP 1443", CLIENT.x + 14, portY, 9, palette.accent);
      mono("→ WSS 443", CLIENT.x + CLIENT.w - 14, portY, 9, palette.muted, "right");
    }

    function drawCore() {
      panel(CORE.x, CORE.y, CORE.w, CORE.h, palette.accent2);
      label("R2O", CORE.x + 14, CORE.y + 17);
      label("ЯДРО", CORE.x + CORE.w - 14, CORE.y + 17);
      var cx = CORE.x + CORE.w / 2;
      var cy = CORE.y + 108;
      var pulse = 1 + Math.sin(clock * 2.2) * 0.03 + corePulse * 0.12;
      context.save();
      context.beginPath();
      context.arc(cx, cy, 38 * pulse, 0, Math.PI * 2);
      context.strokeStyle = rgba(palette.accent, 0.14 + corePulse * 0.16);
      context.lineWidth = 10;
      context.stroke();
      context.beginPath();
      context.arc(cx, cy, 30, 0, Math.PI * 2);
      context.strokeStyle = rgba(palette.accent, 0.6);
      context.lineWidth = 1.4;
      context.stroke();
      context.beginPath();
      for (var i = 0; i < 6; i++) {
        var angle = -Math.PI / 2 + i * Math.PI / 3;
        var px = cx + Math.cos(angle) * 21;
        var py = cy + Math.sin(angle) * 21;
        if (i === 0) context.moveTo(px, py); else context.lineTo(px, py);
      }
      context.closePath();
      context.fillStyle = rgba(palette.accent, 0.1 + corePulse * 0.12);
      context.fill();
      context.strokeStyle = rgba(palette.accent, 0.9);
      context.lineWidth = 1.5;
      context.stroke();
      context.restore();
      text(String(view.activeConnections), cx, cy + 1, '600 20px "Unbounded", sans-serif', palette.text, "center", "middle");
      mono("сессий", cx, cy + 17, 8, palette.muted);

      text("MTProto → WSS", cx, CORE.y + 162, '600 10px "Manrope", sans-serif', palette.text, "center");
      mono(fitText(view.transportLabel || "маршрут не выбран", CORE.w - 28, '9px "IBM Plex Mono", monospace'), cx, CORE.y + 179, 9, palette.accent, "center");
      mono(fitText(view.dcLabel || "DC неизвестен", CORE.w - 28, '9px "IBM Plex Mono", monospace'), cx, CORE.y + 195, 9, palette.muted, "center");

      // Пять ворот прохождения: DNS → TCP → TLS → WebSocket → MTProto.
      var maxGate = 0;
      var failedGate = 0;
      view.lanes.forEach(function (lane) {
        if (Number(lane.passedGate) > maxGate) maxGate = Number(lane.passedGate);
        if (lane.status === "failed" && Number(lane.failureStage) > failedGate) failedGate = Number(lane.failureStage);
      });
      var gateY = CORE.y + 224;
      mono("этапы", CORE.x + 14, gateY - 12, 8, palette.muted);
      GATES.forEach(function (gate, index) {
        var gateX = CORE.x + 14 + index * 27;
        var tone = failedGate === index + 1 ? palette.failure : maxGate >= index + 1 ? palette.accent : palette.line;
        roundRect(gateX, gateY, 22, 12, 2);
        context.fillStyle = rgba(tone, maxGate >= index + 1 ? 0.16 : 0.05);
        context.fill();
        context.strokeStyle = rgba(tone, 0.55);
        context.stroke();
        mono(gate, gateX + 11, gateY + 6, 7, maxGate >= index + 1 ? tone : palette.muted, "center");
      });
      if (snapshot && Number(snapshot.last_success_latency_ms) >= 0 && Number(snapshot.last_success_dc) > 0) {
        mono("ответ DC" + snapshot.last_success_dc + " · " + latencyText(snapshot.last_success_latency_ms),
          cx, CORE.y + CORE.h - 18, 8, palette.confirmed, "center");
      } else {
        mono("ответов пока нет", cx, CORE.y + CORE.h - 18, 8, palette.muted, "center");
      }
    }

    function drawRouteRow(lane, index) {
      var top = rowTop(index);
      var color = laneColor(lane);
      var status = routeStatus(lane);
      var alpha = status === "idle" ? 0.34 : 1;
      context.save();
      roundRect(ROW_X, top, ROW_W, ROW_H, 6);
      context.fillStyle = status === "idle" ? rgba(palette.surface, 0.38) : rgba(color, 0.07);
      context.fill();
      context.strokeStyle = rgba(status === "idle" ? palette.line : color, status === "idle" ? 0.45 : 0.32);
      context.lineWidth = 1;
      context.stroke();
      // Цветной рельс состояния.
      roundRect(ROW_X, top + 8, 2, ROW_H - 16, 1);
      context.fillStyle = rgba(color, alpha);
      context.fill();
      context.restore();

      mono(("0" + (index + 1)).slice(-2), ROW_X + 11, top + 15, 8, palette.muted);
      text(fitText(lane.label, ROW_W - 92, '600 10px "Manrope", sans-serif'), ROW_X + 31, top + 15, '600 10px "Manrope", sans-serif', status === "idle" ? palette.muted : palette.text, "left", "middle");
      var stateWord = ROUTE_WORDS[status] || status;
      if (status === "failed" && Number(lane.failureStage)) stateWord += " · " + (FAILURE_STAGES[Number(lane.failureStage)] || "сбой");
      if (status === "cooldown" && Number(lane.cooldownRemainingMs)) stateWord += " · " + Math.ceil(Number(lane.cooldownRemainingMs) / 1000) + " с";
      chipRight(stateWord, ROW_X + ROW_W - 8, top + 14, color, { font: '8px "IBM Plex Mono", monospace', height: 16, pad: 5 });
      mono(fitText(countsText(lane), ROW_W - 44, '7.5px "IBM Plex Mono", monospace'), ROW_X + 31, top + 31, 7.5, status === "idle" ? palette.muted : palette.text);
      // Дорожка маршрута и пакеты.
      line(ROW_X + 12, top + ROW_H - 8, ROW_X + ROW_W - 12, top + ROW_H - 8, status === "idle" ? palette.line : color, status === "idle" ? 0.45 : 0.3, 1);
      if (status !== "idle") {
        line(ROW_X + 12, top + ROW_H - 8, ROW_X + ROW_W - 12, top + ROW_H - 8,
          color, status === "failed" ? 0.55 : 0.8, 1.6, [3, 9], -clock * 28);
      }
      if (Number(lane.cooldownRemainingMs) > 0 && Number(view.cooldownDurationMs) > 0) {
        var ratio = clamp(Number(lane.cooldownRemainingMs) / Number(view.cooldownDurationMs), 0, 1);
        line(ROW_X + 12, top + ROW_H - 8, ROW_X + 12 + (ROW_W - 24) * ratio, top + ROW_H - 8, palette.warning, 0.85, 2);
      }
    }

    function drawRoutes() {
      panel(ROUTES_BOARD.x, ROUTES_BOARD.y, ROUTES_BOARD.w, ROUTES_BOARD.h, palette.surface);
      label("МАРШРУТЫ", ROUTES_BOARD.x + 14, ROUTES_BOARD.y + 17);
      label("4 КАНАЛА", ROUTES_BOARD.x + ROUTES_BOARD.w - 14, ROUTES_BOARD.y + 17);
      view.lanes.forEach(drawRouteRow);
    }

    function drawDcRow(index) {
      var activity = (view.dcActivity && view.dcActivity[index]) || { active: 0, media: 0, confirmed: 0 };
      var top = dcTop(index);
      var active = Number(activity.active) || 0;
      var media = Number(activity.media) || 0;
      var confirmed = Number(activity.confirmed) || 0;
      var color = active > 0 ? palette.confirmed : confirmed > 0 ? palette.accent : palette.muted;
      context.save();
      roundRect(DC_X, top, DC_W, DC_H, 5);
      context.fillStyle = active > 0 ? rgba(color, 0.09) : rgba(palette.surface, 0.32);
      context.fill();
      context.strokeStyle = rgba(active > 0 ? color : palette.line, active > 0 ? 0.36 : 0.4);
      context.lineWidth = 1;
      context.stroke();
      context.restore();
      dot(DC_X + 10, top + 13, color, 2);
      mono("DC" + (index + 1), DC_X + 18, top + 13, 9, active > 0 ? palette.text : palette.muted);
      var value = active > 0 ? String(active) : "—";
      mono(value, DC_X + DC_W - 10, top + 13, 11, active > 0 ? color : palette.muted, "right");
      var detail = active > 0
        ? (media ? "media " + media : "сессий") + (confirmed ? " · ✓" + confirmed : "")
        : "нет сессий";
      mono(fitText(detail, DC_W - 30, '7.5px "IBM Plex Mono", monospace'), DC_X + 18, top + 28, 7.5, palette.muted);
      if (active > 0) {
        var ghost = 1 + Math.sin(clock * 2 + index) * 0.06 + dcPulse[index] * 0.2;
        context.save();
        context.beginPath();
        context.arc(DC_X + DC_W - 12, top + 28, 3.2 * ghost, 0, Math.PI * 2);
        context.fillStyle = rgba(color, 0.75);
        context.fill();
        context.restore();
      }
    }

    function drawDcs() {
      panel(DC_BOARD.x, DC_BOARD.y, DC_BOARD.w, DC_BOARD.h, palette.surface);
      label("TELEGRAM DC", DC_BOARD.x + 14, DC_BOARD.y + 17);
      label("5 УЗЛОВ", DC_BOARD.x + DC_BOARD.w - 14, DC_BOARD.y + 17);
      for (var i = 0; i < 5; i += 1) drawDcRow(i);
    }

    function drawConnections() {
      // Клиент → ядро.
      line(CLIENT.x + CLIENT.w, 208, CORE.x, 208, palette.accent, 0.45, 2);
      if (!prefersReduced()) line(CLIENT.x + CLIENT.w, 208, CORE.x, 208, palette.accent, 0.85, 1.4, [2, 7], -clock * 34);
      dot(CLIENT.x + CLIENT.w + 2, 208, palette.accent, 2);
      // Ядро → четыре маршрута.
      view.lanes.forEach(function (lane, index) {
        var color = laneColor(lane);
        path([
          [CORE.x + CORE.w, 208],
          [CORE.x + CORE.w + 10, 208],
          [CORE.x + CORE.w + 10, rowCenter(index)],
          [ROW_X, rowCenter(index)]
        ], color, lane.status === "idle" ? 0.16 : 0.3, 1);
      });
      // Маршруты → выбранные DC по живым сессиям.
      var busX = ROW_X + ROW_W + 16;
      line(busX, dcCenter(0), busX, dcCenter(4), palette.line, 0.32, 1);
      var drawn = 0;
      (view.sessions || []).forEach(function (session) {
        if (drawn >= 12) return;
        var dc = dcNumber(session.dc);
        if (dc === null) return;
        var selected = laneIndex(session.selected_transport);
        var fallback = laneIndex(session.fallback_transport);
        var direct = laneIndex(session.direct_transport);
        var lane = selected >= 0 ? selected : fallback >= 0 ? fallback : direct >= 0 ? direct : -1;
        if (lane < 0) return;
        var color = session.telegram_response_seen === true ? palette.confirmed
          : session.selected_transport ? palette.accent : palette.warning;
        var points = dcPath(session, lane);
        if (!points) return;
        path(points, color, 0.24, 1);
        if (!prefersReduced()) {
          context.save();
          context.beginPath();
          context.moveTo(points[0][0], points[0][1]);
          for (var p = 1; p < points.length; p += 1) context.lineTo(points[p][0], points[p][1]);
          context.strokeStyle = rgba(color, 0.55);
          context.lineWidth = 1;
          context.setLineDash([2, 8]);
          context.lineDashOffset = -clock * 30;
          context.stroke();
          context.restore();
        }
        drawn += 1;
      });
      if (!drawn) {
        for (var i = 0; i < 5; i += 1) line(busX, dcCenter(i), DC_X, dcCenter(i), palette.line, 0.24, 1, [2, 4]);
      }
    }

    function particlePoint(particle) {
      return particle.kind === "dc"
        ? pointOnPolyline(particle.points, particle.progress)
        : [particle.x1 + (particle.x2 - particle.x1) * particle.progress,
          particle.y1 + (particle.y2 - particle.y1) * particle.progress];
    }

    function burstSparks(x, y, color) {
      for (var i = 0; i < 5; i += 1) {
        var angle = Math.random() * Math.PI * 2;
        var speed = 18 + Math.random() * 26;
        sparks.push({
          x: x, y: y, vx: Math.cos(angle) * speed, vy: Math.sin(angle) * speed,
          age: 0, life: .35 + Math.random() * .2, color: color
        });
      }
    }

    function drawParticles() {
      context.save();
      context.globalCompositeOperation = "lighter";
      // Хвост из нескольких затухающих точек — как поток пакетов, а не одна искра.
      particles.forEach(function (particle) {
        var point = particlePoint(particle);
        var trail = particle.trail || [];
        for (var i = 0; i < trail.length; i += 1) {
          var weight = (i + 1) / trail.length;
          context.save();
          context.beginPath();
          context.arc(trail[i][0], trail[i][1], 1.1 + weight * 1.6, 0, Math.PI * 2);
          context.fillStyle = rgba(particle.color, 0.06 + weight * 0.3);
          context.fill();
          context.restore();
        }
        context.save();
        context.shadowColor = rgba(particle.color, 0.95);
        context.shadowBlur = 14;
        context.beginPath();
        context.arc(point[0], point[1], 3.1, 0, Math.PI * 2);
        context.fillStyle = rgba(particle.color, 1);
        context.fill();
        context.beginPath();
        context.arc(point[0], point[1], 6, 0, Math.PI * 2);
        context.strokeStyle = rgba(particle.color, 0.22);
        context.lineWidth = 1;
        context.stroke();
        context.restore();
      });
      sparks.forEach(function (spark) {
        context.save();
        context.beginPath();
        context.moveTo(spark.x, spark.y);
        context.lineTo(spark.x - spark.vx * .025, spark.y - spark.vy * .025);
        context.strokeStyle = rgba(spark.color, Math.max(0, 1 - spark.age / .55));
        context.lineWidth = 1.2;
        context.lineCap = "round";
        context.stroke();
        context.restore();
      });
      context.restore();
      pulses.forEach(function (pulse) {
        context.save();
        context.beginPath();
        context.arc(pulse.x, pulse.y, pulse.radius, 0, Math.PI * 2);
        context.strokeStyle = rgba(pulse.color, pulse.alpha);
        context.lineWidth = 1.4;
        context.stroke();
        context.restore();
      });
    }

    function drawLegend(width, height) {
      var y = height - 31;
      var items = [
        [palette.accent2, "активен"],
        [palette.warning, "подключение / пауза"],
        [palette.failure, "отказ"],
        [palette.muted, "резерв"]
      ];
      var x = 24;
      items.forEach(function (item) {
        dot(x + 3, y, item[0], 2.2);
        mono(item[1], x + 10, y, 8, palette.muted);
        x += 22 + measure(item[1], '8px "IBM Plex Mono", monospace');
      });
      var note = view.truncated ? "выборка сессий ограничена" : view.cooldowns.length ? "часть маршрутов на паузе" : "";
      if (!note && snapshot) {
        var last = Number(snapshot.last_failure_stage) ? "последний сбой: " + (FAILURE_STAGES[Number(snapshot.last_failure_stage)] || "маршрут") : "";
        if (last) note = last;
      }
      if (note) mono(note, width - 24, y, 8, palette.muted, "right");
      line(0, height - 52, width, height - 52, palette.line, 0.4, 1);
    }

    function drawDesktop() {
      drawBackground(WIDTH, HEIGHT);
      drawStatus(WIDTH);
      drawConnections();
      drawClient();
      drawCore();
      drawRoutes();
      drawDcs();
      drawParticles();
      drawLegend(WIDTH, HEIGHT);
    }

    /* ─── Мобильная схема: та же информация, но вертикально и крупнее. ─── */

    function drawMobileStatus() {
      var state = STATE_WORDS[view.state] || String(view.state || "—").toUpperCase();
      var stateColor = view.state === "active" || view.state === "mixed" ? palette.accent2
        : view.state === "unavailable" || view.state === "stale" ? palette.failure
          : view.state === "idle" ? palette.muted : palette.warning;
      chip(state, 16, 30, stateColor, { font: '600 10px "IBM Plex Mono", monospace' });
      mono(view.activeConnections + " активных · " + view.acceptedConnections + " принято", MOBILE_WIDTH - 16, 30, 8.5, palette.muted, "right");
      if (view.transportLabel) {
        mono(shortText(view.transportLabel, 34), 16, 50, 8, palette.text);
        mono(shortText(view.dcLabel || "DC неизвестен", 24), MOBILE_WIDTH - 16, 50, 8, palette.accent, "right");
      }
      line(0, 62, MOBILE_WIDTH, 62, palette.line, 0.5, 1);
    }

    function drawMobileClient() {
      var x = 16, y = 74, w = MOBILE_WIDTH - 32, h = 86;
      panel(x, y, w, h, palette.surface);
      label("КЛИЕНТ", x + 12, y + 16);
      text(String(view.activeConnections), x + 12, y + 45, '600 26px "Unbounded", sans-serif', palette.text, "left", "middle");
      mono("активных", x + 13, y + 63, 8, palette.muted);
      var stats = [
        ["принято", String(view.acceptedConnections)],
        ["медиа", String(view.mediaSessions)],
        ["сессий", String(view.sessions.length) + (view.truncated ? "+" : "")]
      ];
      stats.forEach(function (item, index) {
        var sx = x + 110 + index * 92;
        mono(item[0], sx, y + 38, 7.5, palette.muted);
        mono(item[1], sx, y + 54, 10, palette.text);
      });
      mono("TCP 1443 → WSS 443", x + w - 12, y + 72, 8, palette.accent, "right");
    }

    function drawMobileCore() {
      var x = 16, y = 170, w = MOBILE_WIDTH - 32, h = 104;
      panel(x, y, w, h, palette.accent2);
      label("R2O · ЯДРО", x + 12, y + 15);
      var cx = x + 34, cy = y + 51, pulse = 1 + Math.sin(clock * 2.2) * 0.04 + corePulse * 0.1;
      context.save();
      context.beginPath();
      context.arc(cx, cy, 21 * pulse, 0, Math.PI * 2);
      context.strokeStyle = rgba(palette.accent, 0.18 + corePulse * 0.16);
      context.lineWidth = 7;
      context.stroke();
      context.beginPath();
      context.arc(cx, cy, 16, 0, Math.PI * 2);
      context.strokeStyle = rgba(palette.accent, 0.7);
      context.lineWidth = 1.2;
      context.stroke();
      context.restore();
      text(String(view.activeConnections), cx, cy + 1, '600 13px "Unbounded", sans-serif', palette.text, "center", "middle");
      text("MTProto → WSS", x + 68, y + 34, '600 9px "Manrope", sans-serif', palette.text);
      mono(shortText(view.transportLabel || "маршрут не выбран", 34), x + 68, y + 48, 8, palette.accent);
      mono(shortText(view.dcLabel || "DC неизвестен", 30), x + 68, y + 61, 8, palette.muted);
      var maxGate = 0, failedGate = 0;
      view.lanes.forEach(function (lane) {
        if (Number(lane.passedGate) > maxGate) maxGate = Number(lane.passedGate);
        if (lane.status === "failed" && Number(lane.failureStage) > failedGate) failedGate = Number(lane.failureStage);
      });
      GATES.forEach(function (gate, index) {
        var gateX = x + 12 + index * 31;
        var tone = failedGate === index + 1 ? palette.failure : maxGate >= index + 1 ? palette.accent : palette.line;
        roundRect(gateX, y + 78, 26, 12, 2);
        context.fillStyle = rgba(tone, maxGate >= index + 1 ? 0.16 : 0.05);
        context.fill();
        context.strokeStyle = rgba(tone, 0.55);
        context.stroke();
        mono(gate, gateX + 13, y + 84, 7, maxGate >= index + 1 ? tone : palette.muted, "center");
      });
    }

    function drawMobileRoutes() {
      var x = 16, y = 286, w = MOBILE_WIDTH - 32, h = 214;
      panel(x, y, w, h, palette.surface);
      label("МАРШРУТЫ", x + 12, y + 15);
      label("4 КАНАЛА", x + w - 12, y + 15);
      var rowX = x + 10, rowW = w - 20, rowH = 43, rowGap = 4, rowStart = y + 26;
      view.lanes.forEach(function (lane, index) {
        var top = rowStart + index * (rowH + rowGap);
        var color = laneColor(lane);
        var status = routeStatus(lane);
        roundRect(rowX, top, rowW, rowH, 5);
        context.fillStyle = status === "idle" ? rgba(palette.surface, 0.38) : rgba(color, 0.07);
        context.fill();
        context.strokeStyle = rgba(status === "idle" ? palette.line : color, status === "idle" ? 0.4 : 0.3);
        context.lineWidth = 1;
        context.stroke();
        roundRect(rowX, top + 7, 2, rowH - 14, 1);
        context.fillStyle = rgba(color, status === "idle" ? 0.35 : 1);
        context.fill();
        mono(("0" + (index + 1)).slice(-2), rowX + 10, top + 12, 7.5, palette.muted);
        text(fitText(lane.label, rowW - 100, '600 9px "Manrope", sans-serif'), rowX + 28, top + 12, '600 9px "Manrope", sans-serif', status === "idle" ? palette.muted : palette.text);
        var stateWord = ROUTE_WORDS[status] || status;
        if (status === "failed" && Number(lane.failureStage)) stateWord += " · " + (FAILURE_STAGES[Number(lane.failureStage)] || "сбой");
        if (status === "cooldown" && Number(lane.cooldownRemainingMs)) stateWord += " · " + Math.ceil(Number(lane.cooldownRemainingMs) / 1000) + " с";
        chipRight(stateWord, rowX + rowW - 7, top + 12, color, { font: '7.5px "IBM Plex Mono", monospace', height: 14, pad: 5 });
        mono(fitText(countsText(lane), rowW - 40, '7px "IBM Plex Mono", monospace'), rowX + 28, top + 26, 7, status === "idle" ? palette.muted : palette.text);
        line(rowX + 10, top + rowH - 6, rowX + rowW - 10, top + rowH - 6, status === "idle" ? palette.line : color, status === "idle" ? 0.4 : 0.28, 1);
        if (status !== "idle" && !prefersReduced()) {
          line(rowX + 10, top + rowH - 6, rowX + rowW - 10, top + rowH - 6, color, 0.8, 1.4, [3, 8], -clock * 30);
        }
        if (!prefersReduced() && (status === "selected" || status === "connecting" || status === "race")) {
          var dotX = rowX + 16 + ((clock * 44 + index * 23) % (rowW - 32));
          dot(dotX, top + rowH - 6, color, 1.8);
        }
        if (Number(lane.cooldownRemainingMs) > 0 && Number(view.cooldownDurationMs) > 0) {
          var ratio = clamp(Number(lane.cooldownRemainingMs) / Number(view.cooldownDurationMs), 0, 1);
          line(rowX + 10, top + rowH - 6, rowX + 10 + (rowW - 20) * ratio, top + rowH - 6, palette.warning, 0.9, 2);
        }
      });
    }

    function drawMobileDcs() {
      var x = 16, y = 510, w = MOBILE_WIDTH - 32, h = 142;
      panel(x, y, w, h, palette.surface);
      label("TELEGRAM DC", x + 12, y + 15);
      label("5 УЗЛОВ", x + w - 12, y + 15);
      for (var i = 0; i < 5; i += 1) {
        var activity = (view.dcActivity && view.dcActivity[i]) || { active: 0, media: 0, confirmed: 0 };
        var top = y + 25 + i * 22;
        var active = Number(activity.active) || 0;
        var color = active > 0 ? palette.confirmed : Number(activity.confirmed) > 0 ? palette.accent : palette.muted;
        roundRect(x + 10, top, w - 20, 18, 4);
        context.fillStyle = active > 0 ? rgba(color, 0.1) : rgba(palette.surface, 0.2);
        context.fill();
        context.strokeStyle = rgba(active > 0 ? color : palette.line, 0.35);
        context.stroke();
        dot(x + 19, top + 9, color, 1.7);
        mono("DC" + (i + 1), x + 27, top + 9, 7.5, active > 0 ? palette.text : palette.muted);
        mono(active > 0 ? active + " " + plural(active, "сессия", "сессии", "сессий") + (activity.media ? " · media " + activity.media : "") + (activity.confirmed ? " · ✓" + activity.confirmed : "") : "нет сессий",
          x + w - 18, top + 9, 7.5, palette.muted, "right");
      }
    }

    function drawMobileLegend() {
      var y = MOBILE_HEIGHT - 25;
      line(0, y - 24, MOBILE_WIDTH, y - 24, palette.line, 0.4, 1);
      dot(19, y, palette.accent2, 2); mono("активен", 27, y, 7.5, palette.muted);
      dot(94, y, palette.warning, 2); mono("подключение", 102, y, 7.5, palette.muted);
      dot(180, y, palette.failure, 2); mono("отказ", 188, y, 7.5, palette.muted);
      dot(232, y, palette.muted, 2); mono("резерв", 240, y, 7.5, palette.muted);
      if (view.truncated) mono("выборка ограничена", MOBILE_WIDTH - 16, y, 7, palette.muted, "right");
    }

    function drawMobile() {
      drawBackground(MOBILE_WIDTH, MOBILE_HEIGHT);
      drawMobileStatus();
      drawMobileClient();
      drawMobileCore();
      drawMobileRoutes();
      drawMobileDcs();
      drawMobileLegend();
    }

    function draw() {
      if (!paletteReady) refreshPalette();
      var width = layoutMobile ? MOBILE_WIDTH : WIDTH;
      var height = layoutMobile ? MOBILE_HEIGHT : HEIGHT;
      context.setTransform(canvas.width / width, 0, 0, canvas.height / height, 0, 0);
      if (layoutMobile) drawMobile(); else drawDesktop();
    }

    function spawnParticle() {
      if (prefersReduced() || layoutMobile) return;
      var now = clock;
      if (now - lastSpawn < 0.22) return;
      lastSpawn = now;
      var activeLanes = view.lanes.filter(function (lane) {
        return lane.counts && (lane.counts.selected || lane.counts.connecting || lane.counts.race);
      });
      if (activeLanes.length) {
        var lane = activeLanes[Math.floor(Math.random() * activeLanes.length)];
        var color = lane.counts && lane.counts.selected ? laneColor(lane) : palette.warning;
        if (particles.length < 40) {
          particles.push({
            kind: "route", color: color, progress: 0, speed: 0.55 + Math.random() * 0.25,
            x1: ROW_X + 12, x2: ROW_X + ROW_W - 12,
            y1: rowTop(lane.index) + ROW_H - 8, y2: rowTop(lane.index) + ROW_H - 8
          });
        }
      }
      var sessions = view.sessions.filter(function (session) {
        return dcNumber(session.dc) !== null && laneIndex(session.selected_transport) >= 0;
      });
      if (sessions.length && particles.length < 40 && Math.random() < 0.7) {
        var session = sessions[Math.floor(Math.random() * sessions.length)];
        var sessionLane = laneIndex(session.selected_transport);
        var points = dcPath(session, sessionLane);
        if (points) {
          particles.push({
            kind: "dc", color: session.telegram_response_seen === true ? palette.confirmed : palette.accent,
            progress: 0, speed: 0.45 + Math.random() * 0.2, points: points
          });
        }
      }
      if (view.activeConnections > 0 && particles.length < 40 && Math.random() < 0.75) {
        particles.push({
          kind: "client", color: palette.accent, progress: 0, speed: 0.85,
          x1: CLIENT.x + CLIENT.w, x2: CORE.x,
          y1: 208, y2: 208
        });
      }
    }

    function tickParticles(delta) {
      for (var i = particles.length - 1; i >= 0; i -= 1) {
        var particle = particles[i];
        particle.progress += delta * particle.speed;
        if (!particle.trail) particle.trail = [];
        particle.trail.push(particlePoint(particle));
        if (particle.trail.length > 7) particle.trail.shift();
        if (particle.progress < 1) continue;
        if (particle.kind === "client") {
          pulses.push({ x: CORE.x, y: 208, radius: 4, alpha: 0.5, color: particle.color, age: 0 });
          burstSparks(CORE.x, 208, particle.color);
        } else if (particle.kind === "route") {
          pulses.push({ x: ROW_X + ROW_W - 12, y: particle.y1, radius: 3, alpha: 0.4, color: particle.color, age: 0 });
          burstSparks(ROW_X + ROW_W - 12, particle.y1, particle.color);
        } else {
          var end = particle.points[particle.points.length - 1];
          pulses.push({ x: end[0], y: end[1], radius: 3, alpha: 0.5, color: particle.color, age: 0 });
          burstSparks(end[0], end[1], particle.color);
        }
        particles.splice(i, 1);
      }
      for (var s = sparks.length - 1; s >= 0; s -= 1) {
        var spark = sparks[s];
        spark.age += delta;
        spark.x += spark.vx * delta;
        spark.y += spark.vy * delta;
        spark.vx *= 0.94;
        spark.vy *= 0.94;
        if (spark.age >= spark.life) sparks.splice(s, 1);
      }
      for (var j = pulses.length - 1; j >= 0; j -= 1) {
        var pulse = pulses[j];
        pulse.age += delta;
        pulse.radius += delta * 18;
        pulse.alpha -= delta * 1.4;
        if (pulse.alpha <= 0 || pulse.age > 0.9) pulses.splice(j, 1);
      }
      corePulse = Math.max(0, corePulse - delta * 2.2);
      for (var k = 0; k < dcPulse.length; k += 1) dcPulse[k] = Math.max(0, dcPulse[k] - delta * 2.4);
      statePulse = Math.max(0, statePulse - delta * 2);
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
      canvas.setAttribute("aria-label", "Схема Telegram-туннеля: " + view.caption + ". Маршруты: " + routes + ". " + dcs + "." + race + truncated);
      canvas.dataset.state = view.state;
      if (root) root.dataset.state = view.state;
      var caption = root && root.querySelector("#tg-flow-caption");
      if (caption && caption.textContent !== view.caption) caption.textContent = view.caption;
    }

    function setView(next) {
      var previous = view;
      view = next || api.summarizeTelegramFlow(null, "");
      if (previous && previous.state !== view.state) { statePulse = 1; corePulse = 1; }
      (view.dcActivity || []).forEach(function (activity, index) {
        var old = previous && previous.dcActivity && previous.dcActivity[index];
        if (old && (old.active !== activity.active || old.confirmed !== activity.confirmed || old.media !== activity.media)) dcPulse[index] = 1;
      });
      updateAccessibility();
    }

    function resize() {
      if (destroyed) return;
      refreshPalette();
      var rect = canvas.getBoundingClientRect();
      var width = Math.max(1, rect.width);
      var height = Math.max(1, rect.height);
      layoutMobile = window.innerWidth <= 760;
      pixelRatio = Math.min(2.5, Math.max(1, window.devicePixelRatio || 1));
      var backingWidth = Math.round(width * pixelRatio);
      var backingHeight = Math.round(height * pixelRatio);
      if (canvas.width !== backingWidth) canvas.width = backingWidth;
      if (canvas.height !== backingHeight) canvas.height = backingHeight;
      draw();
      startLoop();
    }

    function updateFrame(now) {
      frameId = 0;
      if (destroyed || !inView || document.hidden || prefersReduced()) { draw(); return; }
      var delta = lastFrame ? Math.min(0.05, (now - lastFrame) / 1000) : 0.016;
      lastFrame = now;
      clock += delta;
      if (now - lastDraw >= 33) {
        spawnParticle();
        tickParticles(delta);
        draw();
        lastDraw = now;
      }
      frameId = window.requestAnimationFrame(updateFrame);
    }

    function startLoop() {
      if (destroyed || frameId || !inView || document.hidden || prefersReduced()) return;
      lastFrame = 0;
      frameId = window.requestAnimationFrame(updateFrame);
    }

    function stopLoop() {
      if (frameId) window.cancelAnimationFrame(frameId);
      frameId = 0;
    }

    function update(nextSnapshot, error) {
      if (destroyed) return null;
      snapshot = nextSnapshot || null;
      maxConnections = Number(snapshot && snapshot.max_connections) || 0;
      var next = api.summarizeTelegramFlow(snapshot, error || undefined);
      setView(next);
      refreshPalette();
      if (prefersReduced() || !inView || document.hidden) draw();
      else startLoop();
      return view;
    }

    function onVisibility() {
      if (document.hidden) stopLoop(); else { refreshPalette(); startLoop(); }
    }

    function onIntersection(entries) {
      inView = Boolean(entries[0] && entries[0].isIntersecting);
      if (inView) startLoop(); else stopLoop();
    }

    function onMotionChange() {
      stopLoop();
      particles.length = 0;
      pulses.length = 0;
      sparks.length = 0;
      if (prefersReduced()) draw(); else startLoop();
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
    if (!intersectionObserver) startLoop();

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
        resizeObserver && resizeObserver.disconnect();
        intersectionObserver && intersectionObserver.disconnect();
        themeObserver && themeObserver.disconnect();
        window.removeEventListener("resize", resize);
        document.removeEventListener("visibilitychange", onVisibility);
        if (reduce && reduce.removeEventListener) reduce.removeEventListener("change", onMotionChange);
        particles.length = 0;
        pulses.length = 0;
        sparks.length = 0;
      }
    };
  }

  global.R2oTelegramPrototype = { mountTelegramFlow: mountTelegramFlow };
})(typeof window !== "undefined" ? window : globalThis);
