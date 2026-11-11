/* R2O — локальная панель. Состояние движка, управление службами и обновления.
   Данные из сети попадают в DOM исключительно через textContent. */
(function (global) {
  "use strict";

  var POLL_MS = 2000;
  var IDLE_POLL_MS = 6000;
  var UPDATE_IDLE_POLL_MS = 60000;
  var STALE_MS = 9000;

  /* ─── Словарь ─── */

  var SHAPES = { 0: "", 1: "TLS 1.3", 2: "TLS 1.2", 3: "QUIC", 4: "любая форма", 5: "голос", 6: "TLS 1.3 + ECH" };
  var MODES = { apply: "применение", observe: "наблюдение", off: "выключен" };

  var TRACK = [
    { label: "Очередь", phases: ["ожидает безопасного слота замера", "заводим поиск"] },
    { label: "Форма", phases: ["ждём форму приветствия"] },
    { label: "Распознаём", phases: ["распознаём поведение"] },
    { label: "Свойства", phases: ["спрашиваем коробку о свойствах"] },
    { label: "Планы", phases: ["выводим планы"] },
    { label: "Проверка", phases: ["проверяем готовое узнанной коробки", "проверяем выведенный план", "проверяем свои планы"] },
    { label: "Подтверждено", phases: ["подтверждено, смотрим живой трафик"] }
  ];
  var VOICE_TRACK = [
    { label: "Замер голоса", phases: ["измеряем живой голосовой поток"] },
    { label: "Приём стоит", phases: ["приём голоса стоит, ждём разговора"] },
    { label: "Ждём ответа", phases: ["приём применился к разговору, ждём ответа сервера"] }
  ];

  var TRACK_ICONS = [
    "M3 5h7M3 8h10M3 11h6",
    "M8 2.2 13.2 5v6L8 13.8 2.8 11V5Z",
    "M8 2.8a5.2 5.2 0 1 0 5.2 5.2M8 8l4-2.4",
    "M3 5h10M3 8h10M3 11h10M5.5 3.5v3M10 6.5v3M7 9.5v3",
    "M3 4h7v9H3zM6 2h7v9",
    "M2 8h8M13 8h1M10 5l3 3-3 3",
    "M3 8.5l3 3 7-7"
  ];
  var VOICE_ICONS = [
    "M2 8h2l1.5-4 2 8 2-6 1.5 2H14",
    "M2 8h2l1.5-3 2 6 2-4 1.5 1H14",
    "M2 8h2l1.5-4 2 8 2-6 1.5 2H14"
  ];

  function plural(n, one, few, many) {
    var m10 = n % 10, m100 = n % 100;
    if (m10 === 1 && m100 !== 11) return one;
    if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return few;
    return many;
  }
  function count(n, one, few, many) { return n + " " + plural(n, one, few, many); }

  function num(v) { return typeof v === "number" && isFinite(v) ? v : null; }
  function list(v) { return Array.isArray(v) ? v : []; }
  function str(v) { return v === undefined || v === null ? "" : String(v); }
  function bodyAttribute(doc, name) {
    var body = doc && doc.body;
    return body && typeof body.getAttribute === "function" ? body.getAttribute(name) : null;
  }

  function shapeLabel(shape, transport) {
    var s = SHAPES[shape];
    if (s) return s;
    if (transport === 17) return "UDP";
    if (transport === 6) return "TCP";
    return "протокол не указан";
  }
  function familyLabel(f) { return f === 6 ? "IPv6" : f === 4 ? "IPv4" : "IP?"; }
  function targetLabel(t) {
    if (t === "@discord-voice") return "Голос Discord";
    return str(t) || "цель без имени";
  }

  function trackFor(phase) {
    var tracks = [TRACK, VOICE_TRACK];
    for (var t = 0; t < tracks.length; t++) {
      for (var i = 0; i < tracks[t].length; i++) {
        if (tracks[t][i].phases.indexOf(phase) >= 0) return { steps: tracks[t], at: i, voice: t === 1 };
      }
    }
    /* Фазы D2O и старых сборок могут отличаться формулировкой. Не оставляем
       карточку без дорожки: узнаём этап по ключевому слову. */
    var text = str(phase).toLowerCase();
    var rules = [
      [/подтвержд/, 6],
      [/провер/, 5],
      [/свойств/, 3],
      [/распозна|классифиц/, 2],
      [/план|вывед/, 4],
      [/форм|приветств/, 1],
      [/очеред|слот|завод|старт/, 0]
    ];
    for (var r = 0; r < rules.length; r++) {
      if (rules[r][0].test(text)) return { steps: TRACK, at: rules[r][1], voice: false };
    }
    return null;
  }

  function parseTime(iso) {
    var t = Date.parse(iso);
    return isFinite(t) && t > 86400000 ? t : null;
  }

  function duration(ms) {
    var s = Math.max(0, Math.floor(ms / 1000));
    if (s < 60) return s + " с";
    var m = Math.floor(s / 60);
    if (m < 60) return m + " мин " + (s % 60 < 10 ? "0" : "") + (s % 60) + " с";
    var h = Math.floor(m / 60);
    if (h < 48) return h + " ч " + (m % 60) + " мин";
    return Math.floor(h / 24) + " дн " + (h % 24) + " ч";
  }
  function telegramRouteName(route) {
    return route === 1 ? "прямой WSS" :
      route === 2 ? "Worker Cloudflare" :
      route === 3 ? "CF proxy" : route === 4 ? "прямой TCP" : "неизвестный маршрут";
  }
  function telegramFailureStage(stage) {
    return stage === 1 ? "DNS" :
      stage === 2 ? "TCP" :
      stage === 3 ? "TLS" :
      stage === 4 ? "WebSocket" :
      stage === 5 ? "MTProto" :
      stage === 6 ? "настройка маршрута" : "неизвестный этап";
  }
  function telegramAge(ms) { return ms < 1000 ? "только что" : duration(ms); }
  function telegramMilliseconds(ms) {
    return Number.isFinite(Number(ms)) ? Math.max(0, Math.round(Number(ms))) + " мс" : "—";
  }
  function telegramBytes(bytes) {
    var value = Math.max(0, Number(bytes) || 0), units = ["Б", "КБ", "МБ", "ГБ"];
    var unit = 0;
    while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
    return (unit ? new Intl.NumberFormat("ru-RU", { maximumFractionDigits: 1 }).format(value) : String(value)) + " " + units[unit];
  }
  function clock(ms) {
    var s = Math.max(0, Math.floor(ms / 1000));
    var m = Math.floor(s / 60), h = Math.floor(m / 60);
    var pad = function (x) { return (x < 10 ? "0" : "") + x; };
    return (h ? h + ":" + pad(m % 60) : m) + ":" + pad(s % 60);
  }
  function ago(ms) {
    if (ms < 45000) return "только что";
    return duration(ms).replace(/ \d+ с$/, "").replace(/ 0 (мин|ч)$/, "") + " назад";
  }
  function localTime(t) {
    try {
      return new Date(t).toLocaleString("ru-RU", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
    } catch (e) { return new Date(t).toISOString(); }
  }

  /* Краткая выжимка плана — только директивы, без полезной нагрузки. */
  function planGist(text) {
    var skip = { "r2o-plan": 1, id: 1, proto: 1, payload: 1, wire: 1, input: 1 };
    return str(text).split("\n").map(function (line) { return line.trim(); }).filter(function (line) {
      return line && !skip[line.split(/\s+/)[0]];
    }).map(function (line) {
      var parts = line.split(/\s+/);
      return parts.length > 3 ? parts.slice(0, 3).join(" ") + "…" : line;
    }).join(" · ");
  }

  /* Кандидат плана — техническая строка. В карточке показываем только
     первый приём и число остальных; полный текст раскрывается по клику. */
  function candidateGist(text) {
    var value = str(text).trim().replace(/^план\s+(?:поставлен|применён|применен|принят)\s*:\s*/i, "");
    var parts = value.split(/\s*·\s*/).filter(Boolean);
    if (!parts.length) return value;
    var first = parts[0];
    if (first.length > 36) first = first.slice(0, 35) + "…";
    return parts.length > 1 ? first + " · ещё " + (parts.length - 1) : first;
  }

  /* Предел одновременных замеров считает движок по нагрузке роутера:
     от 1 на слабом до десятков на мощном. До 16 — клетками, больше — шкалой. */
  function slotsView(meas) {
    var limit = Math.max(0, Math.round(num(meas && meas.limit) || 0));
    var active = Math.max(0, Math.round(num(meas && meas.active) || 0));
    var queued = Math.max(0, Math.round(num(meas && meas.queued) || 0));
    var measured = num(meas && meas.free_pct) !== null;
    return {
      kind: limit <= 16 ? "cells" : "bar",
      limit: limit, active: Math.min(active, Math.max(limit, active)), queued: queued,
      short: measured ? "предел по нагрузке роутера" : "предел по умолчанию",
      note: measured
        ? "Сколько замеров идёт одновременно, решает движок: предел снижается, когда роутеру не хватает процессора, памяти или conntrack, и растёт, когда есть запас и очередь."
        : "Данных о нагрузке роутера нет — движок держит предел по умолчанию."
    };
  }

  function normName(n) { return str(n).toLowerCase().replace(/\.$/, ""); }

  /* Привязка, уже покрытая применяемым семейством, не дублируется как отдельный результат.
     Исключения семейства остаются видимыми. */
  function coveredBy(binding, groups) {
    if (binding.kind && binding.kind !== "name") return null;
    var name = normName(binding.target);
    for (var i = 0; i < groups.length; i++) {
      var g = groups[i];
      var suffix = normName(g.suffix);
      if (!g.active || (binding.transport || 6) !== g.transport || (binding.family || 4) !== g.family ||
          (binding.shape || 0) !== g.shape ||
          (binding.probe_path || "/") !== (g.probe_path || "/") ||
          (binding.ech_origin || "") !== (g.ech_origin || "")) continue;
      if (name !== suffix && name.slice(-suffix.length - 1) !== "." + suffix) continue;
      var excepted = list(g.exceptions).some(function (ex) {
        return normName(ex && typeof ex === "object" ? ex.name : ex) === name;
      });
      if (!excepted) return g;
    }
    return null;
  }

  /* ─── Модель: что можно честно утверждать по снимку ─── */

  function model(status, received, now) {
    var snap = (status && status.snapshot) || {};
    var k = (status && status.knowledge) || {};
    var linked = !!k.linked;
    var engine = !!snap.engine_running;
    var searches = linked ? list(k.searches) : [];
    var QUEUED = "ожидает безопасного слота замера";
    var active = searches.filter(function (s) { return s.phase !== "подтверждено, смотрим живой трафик"; });
    var m = {
      snap: snap, k: k, linked: linked, engine: engine,
      fresh: snap.live_fresh !== false,
      searches: searches, hunting: active.length,
      running: searches.filter(function (s) { return s.phase !== QUEUED; }),
      queued: searches.filter(function (s) { return s.phase === QUEUED; }),
      groups: list(k.groups), boxes: list(k.boxes),
      mode: str(snap.mode) || "observe"
    };

    if (!engine) {
      m.tone = "bad"; m.lamp = "bad";
      m.headline = ["Движок ", "остановлен"];
      m.state = "Движок остановлен";
      m.lede = m.snap.mode === "off"
        ? "В конфигурации задан режим MODE=off. Трафик не читается и обходы не применяются."
        : "Трафик не читается, подбор не идёт, сохранённые обходы не применяются. Каталог ниже — последнее сохранённое состояние.";
    } else if (!linked) {
      m.tone = "bad"; m.lamp = "warn";
      m.headline = ["Нет связи ", "с датапатом"];
      m.state = "Движок запущен, связи с датапатом нет";
      m.lede = (k.link_note ? "Причина: " + k.link_note + ". " : "") +
        "Идут ли поиски и применяются ли обходы, отсюда не видно. Это не «ноль поисков», а отсутствие измерения.";
    } else if (m.hunting > 0) {
      m.tone = "live"; m.lamp = "live";
      m.headline = ["Идёт ", count(m.hunting, "поиск", "поиска", "поисков")];
      m.state = "Движок работает, идёт подбор";
      m.lede = "R2O подтвердил блокировку и сам подбирает обход в протоколе, где она встретилась. Делать ничего не нужно." +
        (m.queued.length ? " Замеряется " + (m.hunting - m.queued.length) + ", " + m.queued.length + " " +
          plural(m.queued.length, "ждёт", "ждут", "ждут") + " свободного слота замера." : "");
    } else {
      m.tone = "ok"; m.lamp = "ok";
      m.headline = ["Поисков ", "нет"];
      m.state = "Движок работает";
      m.lede = "Подтверждённых блокировок без решения сейчас нет. Живой трафик под наблюдением: подбор начнётся, только если блокировка подтвердится измерением.";
    }
    if (engine && !m.fresh) {
      m.lamp = "warn";
      m.state = "Снимок движка устарел";
    }
    /* uptime_seconds — время работы процесса панели, а не движка. */
    m.panelUptime = num(snap.uptime_seconds);
    m.stateDetail = "режим: " + (MODES[m.mode] || m.mode);
    return m;
  }

  /* ─── Движение ───
     GSAP — локальный /assets/gsap.js. Без него (или при «уменьшить движение»)
     панель полностью работает: состояния выставляются сразу, без переходов. */

  var Motion = (function () {
    var g = global && global.gsap;
    var doc = global && global.document;
    var mq = global && global.matchMedia ? global.matchMedia("(prefers-reduced-motion: reduce)") : null;
    if (g) {
      var plugins = [global.Flip, global.MotionPathPlugin, global.DrawSVGPlugin, global.MorphSVGPlugin,
        global.ScrollToPlugin, global.SplitText, global.CustomEase, global.CustomWiggle].filter(Boolean);
      if (plugins.length) g.registerPlugin.apply(g, plugins);
      if (global.CustomEase) global.CustomEase.create("r2o", ".16,1,.3,1");
      g.defaults({ ease: global.CustomEase ? "r2o" : "power3.out", duration: 0.35 });
      if (global.CustomWiggle) global.CustomWiggle.create("r2oShake", { wiggles: 5, type: "easeOut" });
      if (doc && doc.documentElement) doc.documentElement.classList.add("has-gsap");
    }
    function on() { return !!g && !(mq && mq.matches); }
    /* Перестроения раскладки (Flip) при смене размера окна завершаются сразу:
       иначе зафиксированные на время анимации размеры вылезают за новый край. */
    var live = [];
    function track(anim) {
      if (anim) { live.push(anim); anim.eventCallback("onComplete", function () { live.splice(live.indexOf(anim), 1); }); }
      return anim;
    }
    if (g && global.addEventListener) global.addEventListener("resize", function () {
      live.splice(0).forEach(function (a) { a.progress(1); });
    });
    return { g: g, on: on, Flip: global && global.Flip, track: track };
  })();

  /* ─── DOM ─── */

  var SVG = "http://www.w3.org/2000/svg";
  var ICONS = {
    play: "M8 5.5v13l10.5-6.5z",
    stop: "M7 7h10v10H7z",
    restart: "M20 11.5a8 8 0 1 1-2.3-5.6M20 4.5v5h-5",
    reapply: "M4 7h11M4 12h16M4 17h9M17 15l3 2-3 2",
    erase: "M5 7h14M9 7V5h6v2M7 7l1 12h8l1-12M10.5 10.5v6M13.5 10.5v6",
    check: "M5 12.5l4.5 4.5L19 7.5",
    cross: "M6.5 6.5l11 11M17.5 6.5l-11 11",
    dash: "M6 12h12",
    send: "M21 3 3 10.5l7 2.5 2.5 7zM10 13l5-5"
  };

  function el(doc, tag, cls, text) {
    var n = doc.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }
  function add(parent) {
    for (var i = 1; i < arguments.length; i++) {
      var c = arguments[i];
      if (c === null || c === undefined || c === false) continue;
      parent.appendChild(typeof c === "string" ? parent.ownerDocument.createTextNode(c) : c);
    }
    return parent;
  }
  function icon(doc, name) {
    var s = doc.createElementNS(SVG, "svg");
    s.setAttribute("viewBox", "0 0 24 24");
    s.setAttribute("aria-hidden", "true");
    var p = doc.createElementNS(SVG, "path");
    p.setAttribute("d", ICONS[name]);
    s.appendChild(p);
    return s;
  }
  function tag(doc, text, tone) {
    var t = el(doc, "span", "tag", text);
    if (tone) t.setAttribute("data-tone", tone);
    return t;
  }

  /* Раздел перерисовывается, только если изменились его данные: так не теряются
     раскрытые подробности, фокус и выделение текста. */
  function section(node, key, build) {
    if (node.__r2oKey === key) return false;
    var open = {};
    var nodes = node.querySelectorAll("details[data-key]");
    for (var i = 0; i < nodes.length; i++) if (nodes[i].open) open[nodes[i].getAttribute("data-key")] = true;
    var fresh = build();
    if (Motion.g) {
      /* Анимации уходящих узлов не должны доживать после перерисовки. */
      var gone = node.querySelectorAll("[style]");
      if (gone.length) Motion.g.killTweensOf(gone);
      var tls = node.querySelectorAll(".box-card, .family-card");
      for (var ti = 0; ti < tls.length; ti++) if (tls[ti].__tl) tls[ti].__tl.kill();
    }
    /* Пересборка не должна проигрывать переходы раскрытия заново: открытые
       карточки на миг схлопывались в 0fr и разворачивались обратно. Пока
       секция собирается, переходы выключены; снимаем запрет после кадра. */
    node.setAttribute("data-rerender", "");
    node.replaceChildren.apply(node, fresh);
    var again = node.querySelectorAll("details[data-key]");
    for (var j = 0; j < again.length; j++) {
      if (!open[again[j].getAttribute("data-key")]) continue;
      /* Программное раскрытие не должно запускать анимацию появления
         содержимого: это выглядело как быстрое сворачивание и разворот. */
      again[j].__restoring = true;
      again[j].open = true;
    }
    var view = (node.ownerDocument && node.ownerDocument.defaultView) || global;
    if (view.requestAnimationFrame) {
      view.requestAnimationFrame(function () {
        view.requestAnimationFrame(function () { node.removeAttribute("data-rerender"); });
      });
    } else {
      node.removeAttribute("data-rerender");
    }
    node.__r2oKey = key;
    return true;
  }

  function App(doc, win) {
    this.doc = doc;
    this.win = win;
    this.status = null;
    this.catalogRevision = null;
    this.lastPoll = 0;
    this.lastUpdatePoll = null;
    this.received = 0;
    this.lastOk = 0;
    this.failed = false;
    this.pending = null;
    this.armed = null;
    this.filter = "";
    this.flash = null;
    this.workerDialog = null;
    this.workerDomains = [];
    this.screen = "now";
    this.screenTitle = "Обзор";
    this.screenKicker = "Пульт";
    this.commandItems = [];
    this.commandIndex = 0;
    this.commandOpened = false;
    this.$ = function (id) { return doc.getElementById(id); };
  }

  App.prototype.trackMastHeight = function () {
    var doc = this.doc, win = this.win;
    var mast = doc.querySelector && doc.querySelector(".mast");
    var root = doc.documentElement;
    if (!mast || !root || !root.style || !root.style.setProperty) return;
    var update = function () {
      root.style.setProperty("--mast-offset", Math.ceil(mast.getBoundingClientRect().height) + "px");
    };
    update();
    if (win.ResizeObserver) {
      this.mastObserver = new win.ResizeObserver(update);
      this.mastObserver.observe(mast);
    } else { win.addEventListener("resize", update); }
  };

  /* Экраны вместо длинной ленты: один активный раздел, глубокие ссылки
     сохраняются в hash, а рабочие данные продолжают обновляться во всех. */
  App.prototype.initRouter = function () {
    var self = this, doc = this.doc, win = this.win;
    this.screens = [].slice.call(doc.querySelectorAll("#app > section[data-screen]"));
    this.screenLinks = [].slice.call(doc.querySelectorAll(".index a[data-nav]"));
    var valid = {};
    this.screens.forEach(function (screen) { valid[screen.id] = screen; });
    this.validScreens = valid;
    var fromHash = function () {
      var id = (win.location.hash || "").replace(/^#/, "");
      return valid[id] ? id : "now";
    };
    doc.addEventListener("click", function (event) {
      var link = event.target.closest ? event.target.closest("a[href^='#']") : null;
      if (!link) return;
      var id = (link.getAttribute("href") || "").replace(/^#/, "");
      if (!valid[id]) return;
      event.preventDefault();
      self.showScreen(id);
    });
    win.addEventListener("hashchange", function () { self.showScreen(fromHash(), { fromHash: true }); });
    this.showScreen(fromHash(), { instant: true, fromHash: true });
  };

  App.prototype.showScreen = function (id, options) {
    options = options || {};
    var doc = this.doc, win = this.win;
    if (!this.validScreens || !this.validScreens[id]) id = "now";
    var screen = this.validScreens[id];
    var previous = this.screen;
    var changed = previous !== id || options.instant;
    this.screen = id;
    this.screenTitle = screen.getAttribute("data-title") || "Обзор";
    this.screenKicker = screen.getAttribute("data-kicker") || "Пульт";
    this.screens.forEach(function (item) { item.hidden = item !== screen; });
    this.screenLinks.forEach(function (link) {
      var current = link.getAttribute("data-nav") === id;
      if (current) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    });
    var kicker = this.$("screen-kicker"), title = this.$("screen-title");
    if (kicker) kicker.textContent = this.screenKicker;
    if (title) title.textContent = this.screenTitle;
    this.updateTitle();
    if (options.fromHash !== true && win.location.hash !== "#" + id && win.history && win.history.pushState) {
      win.history.pushState(null, "", "#" + id);
    }
    if (!changed) return;
    if (win.scrollTo) win.scrollTo(0, 0);
    if (options.fromHash === true) {
      var resetScroll = function () { if (win.scrollTo) win.scrollTo(0, 0); };
      if (win.requestAnimationFrame) win.requestAnimationFrame(resetScroll);
      else win.setTimeout(resetScroll, 0);
    }
    if (id === "telegram") {
      var body = this.$("telegram-body");
      if (body && body.__tgUi && body.__tgUi.scene && body.__tgUi.scene.__flow) {
        body.__tgUi.scene.__flow.attach();
      }
      if (this.m) this.renderTelegram(this.m, true);
    }
    if (Motion.on() && !options.instant) {
      var g = Motion.g;
      var parts = [].slice.call(screen.querySelectorAll(".screen-head, .status-panel, .overview-metric, .metric-card, .card, .family-card, .box-card, .diag-card, .tg-flow, .release-hero, .diag-history"));
      if (screen.id === "now") parts = [].slice.call(screen.querySelectorAll(".status-panel, .overview-metrics, .workload-card, .overview-side > *"));
      g.killTweensOf(screen);
      g.killTweensOf(parts);
      Motion.track(g.timeline({ defaults: { ease: "power3.out", clearProps: "all" } })
        .fromTo(screen, { autoAlpha: 0, y: 7 }, { autoAlpha: 1, y: 0, duration: 0.24 }, 0)
        .fromTo(parts, { y: 10, autoAlpha: 0 }, { y: 0, autoAlpha: 1, duration: 0.3, stagger: 0.02 }, 0.03));
    }
  };

  App.prototype.updateTitle = function () {
    var live = this.m && this.m.hunting ? "● " : "";
    this.doc.title = live + "R2O — " + (this.screenTitle || "Обзор");
  };

  App.prototype.navigate = function (id) {
    if (!this.validScreens || !this.validScreens[id]) return;
    if (this.doc.location.hash === "#" + id) this.showScreen(id, { instant: false });
    else this.doc.location.hash = "#" + id;
  };

  /* Командная палитра: единая точка входа в разделы и найденные сущности. */
  App.prototype.initCommand = function () {
    var self = this, doc = this.doc;
    var dialog = this.$("command"), input = this.$("command-input"), list = this.$("command-list");
    if (!dialog || !input || !list) return;
    this.commandDialog = dialog;
    this.commandInput = input;
    this.commandList = list;
    var openers = [this.$("command-open"), this.$("command-hint")];
    openers.forEach(function (button) { if (button) button.addEventListener("click", function () { self.openCommand(); }); });
    input.addEventListener("input", function () { self.renderCommand(input.value); });
    input.addEventListener("keydown", function (event) {
      if (event.key === "ArrowDown") { event.preventDefault(); self.moveCommand(1); }
      else if (event.key === "ArrowUp") { event.preventDefault(); self.moveCommand(-1); }
      else if (event.key === "Enter") { event.preventDefault(); self.chooseCommand(); }
    });
    list.addEventListener("click", function (event) {
      var button = event.target.closest ? event.target.closest(".command-item") : null;
      if (!button) return;
      self.commandIndex = Number(button.getAttribute("data-index")) || 0;
      self.chooseCommand();
    });
    dialog.addEventListener("click", function (event) { if (event.target === dialog) dialog.close(); });
    dialog.addEventListener("close", function () { self.commandOpened = false; });
  };

  App.prototype.openCommand = function () {
    var dialog = this.commandDialog, input = this.commandInput;
    if (!dialog || !input) return;
    this.commandOpened = true;
    this.commandIndex = 0;
    input.value = "";
    this.renderCommand("");
    if (typeof dialog.showModal === "function") {
      if (!dialog.open) dialog.showModal();
    } else if (!dialog.hasAttribute("open")) dialog.setAttribute("open", "");
    input.focus();
  };

  App.prototype.commandCatalog = function () {
    var self = this, m = this.m;
    var out = [];
    var maps = [
      { id: "now", title: "Обзор", meta: "Состояние движка и живые поиски", icon: "i-overview" },
      { id: "families", title: "Семейства", meta: "Подтверждённые суффиксы и исключения", icon: "i-families" },
      { id: "boxes", title: "Коробки", meta: "Поведение блокировок, планы и привязки", icon: "i-boxes" },
      { id: "telegram", title: "Telegram-туннель", meta: "Служба, маршруты DC1–DC5 и Workers", icon: "i-telegram" },
      { id: "updates", title: "Обновления", meta: "Выпуски, автообновление и заметки", icon: "i-updates" },
      { id: "diagnostics", title: "Диагностика", meta: "Цепочка движка, память и подборы", icon: "i-diagnostics" }
    ];
    maps.forEach(function (item) {
      out.push({ kind: "route", route: item.id, title: item.title, meta: item.meta, icon: item.icon });
    });
    if (!m) return out;
    m.groups.forEach(function (group) {
      var evidenceCount = num(group.evidence_count) || list(group.evidence).length;
      out.push({
        kind: "family", route: "families", filter: str(group.suffix),
        title: "*." + str(group.suffix),
        meta: "Семейство · " + count(evidenceCount, "домен", "домена", "доменов") + " · " + shapeLabel(group.shape, group.transport),
        icon: "i-families"
      });
    });
    m.boxes.forEach(function (box, index) {
      var sigs = list(box.signals);
      var first = sigs.length ? (str(sigs[0].human) || str(sigs[0].kind)) : "приметы не записаны";
      out.push({
        kind: "box", route: "boxes", boxId: str(box.id),
        title: "Коробка " + (index + 1) + " · " + str(box.id),
        meta: first + " · " + count(list(box.bindings).length, "цель", "цели", "целей"),
        icon: "i-boxes"
      });
    });
    return out;
  };

  App.prototype.renderCommand = function (query) {
    var doc = this.doc, list = this.commandList, empty = this.$("command-empty");
    if (!list) return;
    var needle = normName(query || "");
    var items = this.commandCatalog().filter(function (item) {
      if (!needle) return true;
      return normName(item.title + " " + item.meta).indexOf(needle) >= 0 ||
        normName(item.filter || "").indexOf(needle) >= 0;
    }).slice(0, 14);
    this.commandItems = items;
    if (this.commandIndex >= items.length) this.commandIndex = Math.max(0, items.length - 1);
    list.replaceChildren();
    if (empty) empty.hidden = items.length > 0;
    items.forEach(function (item, index) {
      var button = el(doc, "button", "command-item");
      button.type = "button";
      button.setAttribute("role", "option");
      button.setAttribute("data-index", String(index));
      button.setAttribute("aria-selected", String(index === this.commandIndex));
      var svg = doc.createElementNS(SVG, "svg");
      svg.setAttribute("viewBox", "0 0 24 24");
      svg.setAttribute("aria-hidden", "true");
      var use = doc.createElementNS(SVG, "use");
      use.setAttribute("href", "#" + item.icon);
      svg.appendChild(use);
      var copy = el(doc, "span", "command-item-copy");
      add(copy, el(doc, "strong", "", item.title), el(doc, "small", "", item.meta));
      var key = el(doc, "kbd", "", item.kind === "route" ? "→" : "↵");
      add(button, svg, copy, key);
      list.appendChild(button);
    }, this);
    this.markCommand();
  };

  App.prototype.markCommand = function () {
    if (!this.commandList) return;
    var buttons = this.commandList.children;
    for (var i = 0; i < buttons.length; i++) {
      var selected = i === this.commandIndex;
      buttons[i].setAttribute("aria-selected", String(selected));
      if (selected && buttons[i].scrollIntoView) buttons[i].scrollIntoView({ block: "nearest" });
    }
  };

  App.prototype.moveCommand = function (step) {
    if (!this.commandItems.length) return;
    this.commandIndex = (this.commandIndex + step + this.commandItems.length) % this.commandItems.length;
    this.markCommand();
  };

  App.prototype.chooseCommand = function () {
    var item = this.commandItems[this.commandIndex];
    if (!item) return;
    if (this.commandDialog) this.commandDialog.close();
    if (item.kind === "route") { this.navigate(item.route); return; }
    if (item.kind === "family") {
      var self = this;
      this.filter = normName(item.filter);
      var input = this.$("filter");
      if (input) input.value = item.filter;
      var clear = this.$("filter-clear");
      if (clear) clear.hidden = false;
      this.renderCatalog(true);
      this.navigate("families");
      this.win.setTimeout(function () { self.focusFamily(item.filter); }, 80);
      return;
    }
    if (item.kind === "box") {
      this.navigate("boxes");
      this.showBox(item.boxId);
    }
  };

  App.prototype.focusFamily = function (suffix) {
    var self = this, doc = this.doc;
    var locate = function () {
      var cards = doc.querySelectorAll("#families-body .family-card");
      for (var i = 0; i < cards.length; i++) {
        var name = cards[i].querySelector(".family-name");
        if (name && normName(name.textContent.replace("*.", "")) === normName(suffix)) {
          cards[i].open = true;
          cards[i].scrollIntoView({ block: "center", behavior: Motion.on() ? "smooth" : "auto" });
          return true;
        }
      }
      return false;
    };
    if (!locate()) {
      this.filter = "";
      var input = this.$("filter");
      if (input) input.value = "";
      this.renderCatalog(true);
      this.win.setTimeout(locate, 60);
    }
  };

  App.prototype.start = function () {
    var self = this, doc = this.doc, win = this.win;
    this.trackMastHeight();
    var input = this.$("filter");
    var clear = this.$("filter-clear");
    input.addEventListener("input", function () {
      self.filter = input.value.trim().toLowerCase();
      if (clear) clear.hidden = !self.filter;
      var flip = Motion.on() && Motion.Flip;
      var state = flip ? Motion.Flip.getState(".family-card, .box-card") : null;
      self.renderCatalog(true);
      if (state) {
        /* Оставшиеся карточки съезжаются; найденные проявляются на месте. */
        Motion.track(Motion.Flip.from(state, {
          targets: doc.querySelectorAll(".family-card, .box-card"),
          duration: 0.28, ease: "power3.inOut", absolute: false, nested: true, scale: true, simple: true,
          onEnter: function (els) { return Motion.g.fromTo(els, { autoAlpha: 0, y: 8 }, { autoAlpha: 1, y: 0, duration: 0.34, clearProps: "transform,opacity,visibility" }); }
        }));
      }
    });
    if (clear) clear.addEventListener("click", function () {
      input.value = "";
      self.filter = "";
      clear.hidden = true;
      self.renderCatalog(true);
      input.focus();
    });
    doc.addEventListener("visibilitychange", function () {
      if (doc.hidden) {
        if (Motion.g) Motion.g.killTweensOf(self.$("update-state"));
        var state = self.$("update-state");
        if (state && state.style) { state.style.opacity = ""; state.style.transform = ""; }
      } else { self.poll(); self.pollUpdates(); }
    });
    doc.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && self.armed) { self.armed = null; self.renderActions(); }
      if ((e.ctrlKey || e.metaKey) && (e.key === "k" || e.key === "K")) {
        e.preventDefault();
        self.openCommand();
        return;
      }
      if (e.key === "/" && doc.activeElement && doc.activeElement.tagName !== "INPUT" && doc.activeElement.tagName !== "TEXTAREA") {
        e.preventDefault(); input.focus();
      }
    });
    this.initRouter();
    this.initCommand();
    this.drawMark();
    this.poll();
    this.initUpdates();
    this.checkUpdates(false);
    win.setInterval(function () { if (!doc.hidden) self.poll(true); }, POLL_MS);
    win.setInterval(function () { if (!doc.hidden) self.pollUpdates(true); }, POLL_MS);
    win.setInterval(function () { self.tick(); }, 1000);
  };

  App.prototype.poll = function (scheduled) {
    var self = this;
    if (this.inflight) return;
    var idle = this.m && !this.m.hunting &&
      (!this.m.snap.engine_running || this.m.linked) &&
      this.m.snap.control_state !== "running" && !this.pending && !this.failed;
    if (scheduled && idle && Date.now() - this.lastPoll < IDLE_POLL_MS) return;
    this.lastPoll = Date.now();
    this.inflight = true;
    var ctrl = typeof AbortController === "function" ? new AbortController() : null;
    var timer = this.win.setTimeout(function () { if (ctrl) ctrl.abort(); }, 5000);
    var url = "/api/status" + (this.catalogRevision ? "?catalog_revision=" + encodeURIComponent(this.catalogRevision) : "");
    this.win.fetch(url, { cache: "no-store", signal: ctrl ? ctrl.signal : undefined })
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then(function (data) {
        if (data.catalog_unchanged === true) {
          if (!self.status || !self.status.knowledge || !data.knowledge ||
              !data.catalog_revision || data.catalog_revision !== self.status.catalog_revision) {
            throw new Error("catalog cache mismatch");
          }
          data.knowledge.boxes = self.status.knowledge.boxes;
          data.knowledge.groups = self.status.knowledge.groups;
        }
        self.catalogRevision = typeof data.catalog_revision === "string" ? data.catalog_revision : null;
        self.status = data;
        self.received = Date.now();
        self.lastOk = self.received;
        self.failed = false;
        self.render();
      })
      .catch(function () {
        self.catalogRevision = null;
        self.failed = true;
        var staleBefore = bodyAttribute(self.doc, "data-stale");
        self.renderNotice();
        var staleAfter = bodyAttribute(self.doc, "data-stale");
        if (self.m && staleBefore !== staleAfter) self.renderTelegram(self.m);
      })
      .then(function () { self.win.clearTimeout(timer); self.inflight = false; });
  };

  /* Автообновление: состояние — update.json (GET /api/update), действия —
     команды router service. Установка перезапускает и панель. */
  App.prototype.initUpdates = function () {
    var self = this;
    if (!this.$("updates-body") || this.updatesInitialized) return;
    this.updatesInitialized = true;
    this.$("update-check").addEventListener("click", function () { return self.checkUpdates(true); });
    this.$("update-install").addEventListener("click", function () {
      if (self.$("update-install").disabled) return;
      return self.updateCommand("install");
    });
    this.$("update-auto").addEventListener("change", function () {
      return self.updateCommand(self.$("update-auto").checked ? "auto-on" : "auto-off");
    });
  };

  App.prototype.updateRequest = function (path, post) {
    var win = this.win, ctrl = typeof AbortController === "function" ? new AbortController() : null;
    var timer = win.setTimeout(function () { if (ctrl) ctrl.abort(); }, 5000);
    return win.fetch(path, {
      method: post ? "POST" : "GET", cache: "no-store", credentials: "same-origin",
      signal: ctrl ? ctrl.signal : undefined
    }).then(function (r) {
      return r.json().then(function (data) { return { ok: r.ok, code: r.status, data: data || {} }; },
        function () { return { ok: false, code: r.status, data: {} }; });
    }).finally(function () { win.clearTimeout(timer); });
  };

  /* Без нажатия — только прочитать состояние: проверка по сети идёт ночью. */
  App.prototype.checkUpdates = function (force) {
    return force ? this.updateCommand("check") : this.pollUpdates();
  };

  var UPDATE_ACTIONS = {
    check: "Проверяем обновления…",
    install: "Устанавливаем обновление. Службы перезапустятся, панель подключится сама…",
    "auto-on": "Включаем автообновление…", "auto-off": "Выключаем автообновление…"
  };

  App.prototype.updateCommand = function (action) {
    var self = this;
    if (!this.$("updates-body") || this.updatePending) return Promise.resolve();
    this.updatePending = { action: action, at: Date.now() };
    this.updateMessage("");
    this.renderUpdates(this.updateStatus);
    return this.updateRequest("/api/control/update-" + action, true).then(function (reply) {
      if (!reply.ok) {
        self.updatePending = null;
        self.updateMessage(reply.code === 409 ? "Служба выполняет другую команду. Повторите через минуту." :
          reply.code === 403 ? "Управление разрешено только с этой панели." : "Команда не выполнена.");
      }
    }).catch(function () {
      /* Ответ на установку теряется законно: панель перезапускается. */
      if (action !== "install") { self.updatePending = null; self.updateMessage("Нет связи с панелью. Повторите позже."); }
    }).finally(function () {
      self.renderUpdates(self.updateStatus);
      return self.pollUpdates();
    });
  };

  App.prototype.updateMessage = function (text) {
    var node = this.$("update-action");
    if (node) { node.textContent = text; node.hidden = !text; }
  };

  App.prototype.pollUpdates = function (scheduled) {
    var self = this;
    if (this.doc.hidden || this.updateInflight || !this.$("updates-body")) return Promise.resolve();
    var idle = !this.updatePending && !this.updateFailed && !(this.updateStatus && this.updateStatus.busy);
    if (scheduled && idle && this.lastUpdatePoll !== null && Date.now() - this.lastUpdatePoll < UPDATE_IDLE_POLL_MS) return Promise.resolve();
    this.lastUpdatePoll = Date.now();
    this.updateInflight = true;
    return this.updateRequest("/api/update").then(function (reply) {
      if (!reply.ok) throw new Error("HTTP " + reply.code);
      var s = reply.data, pending = self.updatePending;
      self.updateFailed = false;
      self.updateStatus = s;
      /* Команда завершена, когда служба снова свободна и состояние новее нажатия
         (установка — когда записан её итог). Тумблер завершается сразу. */
      if (pending && !s.busy) {
        var since = Math.floor(pending.at / 1000) - 5;
        var done = pending.action === "install" ? num(s.last_utc) >= since :
          pending.action === "check" ? num(s.checked_utc) >= since : true;
        if (done || Date.now() - pending.at > 15 * 60000) self.updatePending = null;
      }
      self.renderUpdates(s);
    }).catch(function () {
      self.updateFailed = true;
      self.renderUpdates(self.updateStatus);
    }).finally(function () { self.updateInflight = false; });
  };

  App.prototype.renderUpdates = function (status) {
    if (!this.$("updates-body")) return;
    if (status) this.updateStatus = status;
    var self = this, s = status || {}, pending = this.updatePending;
    var absent = !!s.absent, latest = s.latest || null, current = str(s.current);
    var busy = str(s.busy), action = busy === "installing" ? "install" : busy === "checking" ? "check" : pending && pending.action;
    var newer = latest && latest.release_id && latest.release_id !== current;
    var failedInstall = s.last_ok === false && num(s.last_utc) > 0 && str(s.last_release) && num(s.last_utc) >= num(s.checked_utc) - 5;
    var tone = "", reason = "", text;
    if (absent) { text = "Автообновление не подключено"; reason = "Эта установка обновляется командой установки."; }
    else if (action === "install" || action === "check") text = UPDATE_ACTIONS[action];
    else if (this.updateFailed && !s.current && !s.never && !latest) { text = "Нет связи с панелью"; tone = "warn"; }
    else if (s.never) text = "Обновления ещё не проверялись";
    else if (failedInstall) { text = "Не удалось установить обновление"; tone = "warn"; reason = str(s.last_message); }
    else if (s.check_ok === false) { text = "Не удалось проверить обновления"; tone = "warn"; reason = str(s.check_error); }
    else if (newer) text = "Доступна версия " + (str(latest.version) || latest.release_id);
    else text = "Установлена последняя версия";
    function write(id, value) { var node = self.$(id); if (node.textContent !== value) node.textContent = value; return node; }
    var body = this.$("updates-body");
    if (body.setAttribute) body.setAttribute("data-mode", absent ? "absent" : "ready");
    write("update-current", absent ? "без автообновления" : current || "не определена");
    var state = this.$("update-state"), changed = state.textContent !== text;
    write("update-state", text);
    if (state.parentElement) state.parentElement.setAttribute("data-tone", tone);
    var lamp = this.$("update-lamp");
    if (lamp) lamp.setAttribute("data-tone", tone || (!absent && !action && s.check_ok === true && !newer ? "ok" : "idle"));
    if (changed && !this.doc.hidden && Motion.on()) {
      Motion.g.killTweensOf(state);
      Motion.g.fromTo(state, { opacity: .55, y: 3 }, { opacity: 1, y: 0, duration: .2, clearProps: "opacity,transform" });
    }
    write("update-reason", reason).hidden = !reason;
    write("update-checked", num(s.checked_utc) > 0 ? "проверено " + localTime(num(s.checked_utc) * 1000) : "проверки ещё не было");
    this.$("update-release").hidden = !newer;
    var empty = this.$("update-empty");
    if (empty) {
      empty.hidden = !!newer;
      empty.textContent = absent ? "Автообновление не подключено. Эта установка обновляется командой установки."
        : s.never ? "Проверьте обновления, чтобы увидеть описание нового выпуска."
          : "Новых выпусков нет. Установленная версия актуальна.";
    }
    write("update-version", newer ? "Что изменилось в " + (str(latest.version) || latest.release_id) : "");
    write("update-notes-text", str(latest && latest.notes) || "Описание изменений не опубликовано.");
    var install = this.$("update-install");
    install.hidden = !newer;
    install.disabled = !!action || absent;
    write("update-install", newer && str(latest.release_id) === str(s.bad_release) ? "Повторить установку вручную" : "Установить сейчас");
    this.$("update-check").disabled = !!action || absent;
    this.$("update-check").setAttribute("data-variant", "ghost");
    write("update-warning", newer ? "Службы кратковременно перезапустятся. Закрытие вкладки не отменяет установку." : "").hidden = !newer;
    this.$("update-progress").hidden = true;
    write("update-progress-text", "").hidden = true;
    var auto = this.$("update-auto");
    if (!(pending && /^auto-/.test(pending.action))) auto.checked = !absent && s.auto !== false;
    auto.disabled = absent || !!action || !!pending;
    var schedule = absent ? "Станет доступно, когда автообновление будет подключено" :
      "Ставит новые выпуски в 03:00–05:00 по времени роутера" + (s.auto === false ? " · выключено: ночью только проверка" : "");
    write("update-schedule", schedule);
    var result = !absent && num(s.last_utc) > 0 && str(s.last_message) ?
      "Последний результат: " + str(s.last_message) + " · " + localTime(num(s.last_utc) * 1000) : "";
    write("update-result", result).hidden = !result;
    var nav = write("nav-updates", absent ? "" : newer ? "новая" : action ? "…" : tone ? "!" : "");
    nav.setAttribute("data-tone", tone || "idle");
    var meta = this.$("updates-meta");
    if (meta) {
      var metaKey = JSON.stringify([absent, current, newer, str(latest && latest.version), tone, action]);
      if (meta.__r2oKey !== metaKey) {
        meta.__r2oKey = metaKey;
        meta.replaceChildren();
        var chip = el(this.doc, "span", "meta-chip", absent ? "без автообновления" : "версия " + (current || "—"));
        if (newer) { chip.setAttribute("data-tone", "live"); chip.textContent = "доступна " + (str(latest.version) || latest.release_id); }
        if (tone) chip.setAttribute("data-tone", tone);
        meta.appendChild(chip);
      }
    }
    if (this.m) this.renderOverview(this.m);
  };

  App.prototype.telegramState = function (m) {
    if (!m) return "stopped";
    var snap = m.snap, stats = snap.telegram_stats;
    var st = TG[snap.telegram_status] ? snap.telegram_status : (snap.telegram_configured ? "stopped" : "not_configured");
    var routeFailure = (st === "connected" || st === "local") && stats && global.R2oTelegramFlow &&
      global.R2oTelegramFlow.hasCurrentRouteFailure(stats);
    return routeFailure ? "unavailable" : st;
  };

  App.prototype.renderOverview = function (m) {
    var doc = this.doc;
    var metrics = this.$("overview-metrics");
    if (!metrics) return;
    var st = this.telegramState(m);
    var info = TG[st] || TG.stopped;
    var stages = list(m.snap.stages);
    var broken = stages.filter(function (stage) { return !stage.built; }).length;
    var update = this.updateStatus || {};
    var newer = update.latest && update.latest.release_id && update.latest.release_id !== str(update.current);
    var bindings = 0;
    m.boxes.forEach(function (box) { bindings += list(box.bindings).length; });
    var meas = m.k.measurements || {};
    var activeMeasures = num(meas.active);
    var limitMeasures = num(meas.limit);
    var freePct = num(meas.free_pct);
    var confirms = num(m.k.confirms) || 0;
    var probes = num(m.k.probes_used) || 0;
    var unfit = num(m.k.client_unfit);

    var panel = this.$("status-panel");
    if (panel) panel.setAttribute("data-tone", m.tone);
    var statusLamp = this.$("status-lamp");
    if (statusLamp) statusLamp.setAttribute("data-tone", m.lamp);
    var statusState = this.$("status-state");
    if (statusState && statusState.textContent !== m.state) statusState.textContent = m.state;

    var metricKey = JSON.stringify([m.hunting, m.queued.length, activeMeasures, limitMeasures, freePct, confirms, probes, unfit, broken]);
    if (metrics.__r2oKey !== metricKey) {
      metrics.__r2oKey = metricKey;
      metrics.replaceChildren();
      var measureValue = activeMeasures !== null && limitMeasures !== null ? activeMeasures + " / " + limitMeasures : "—";
      var measureNote = freePct !== null ? "свободно CPU " + freePct + "%" : "лимит не указан";
      var items = [
        { route: "now", label: "Поиски", value: String(m.hunting), note: m.queued.length ? "в очереди " + m.queued.length : "очередь пуста", tone: m.hunting ? "live" : "" },
        { route: "now", label: "Замеры", value: measureValue, note: measureNote, tone: "" },
        { route: "now", label: "Очередь", value: String(m.queued.length), note: m.queued.length ? "ждут свободного слота" : "нет ожидающих", tone: m.queued.length ? "warn" : "" },
        { route: "families", label: "Подтверждения", value: String(confirms), note: "за сессию", tone: confirms ? "ok" : "" },
        { route: "diagnostics", label: "Зонды", value: String(probes), note: "отправлено", tone: "" },
        { route: "diagnostics", label: "План не подошёл", value: unfit === null ? "—" : String(unfit), note: "клиент не принял", tone: unfit ? "warn" : "" }
      ];
      items.forEach(function (item) {
        var card = item.route === "now" ? el(doc, "div", "metric-card") : el(doc, "a", "metric-card");
        if (item.route !== "now") card.href = "#" + item.route;
        card.setAttribute("data-route", item.route);
        var top = el(doc, "div", "metric-top");
        add(top, el(doc, "span", "metric-label", item.label));
        var value = el(doc, "div", "metric-value", item.value);
        value.setAttribute("data-tone", item.tone || "idle");
        add(card, top, value, el(doc, "div", "metric-note", item.note));
        metrics.appendChild(card);
      });
      if (Motion.on() && metrics.children.length && !metrics.__r2oSeen) {
        /* Появление карточек — только при первом построении. При каждом
           обновлении цифр повторять его нельзя: сетка мигает на опросе. */
        metrics.__r2oSeen = true;
        Motion.g.fromTo(metrics.children, { y: 4, autoAlpha: 0 }, { y: 0, autoAlpha: 1, duration: 0.2, stagger: 0.02, ease: "power2.out", clearProps: "all" });
      } else if (metrics.children.length) {
        metrics.__r2oSeen = true;
      }
    }

    var services = this.$("overview-services");
    if (services) {
      var updateState = newer ? "доступна " + (str(update.latest.version) || update.latest.release_id) :
        update.absent ? "не подключено" : update.never || !update.checked_utc ? "не проверялось" : "актуальна";
      var updateTone = newer ? "live" : update.check_ok === false || update.last_ok === false ? "warn" : "";
      var diagState = broken ? "требует внимания" : "цепочка собрана";
      var serviceKey = JSON.stringify([st, info.word, updateState, updateTone, broken, m.snap.telegram_stats]);
      if (services.__r2oKey !== serviceKey) {
        services.__r2oKey = serviceKey;
        services.replaceChildren();
        [
          { route: "telegram", icon: "i-telegram", title: "Telegram-туннель", note: info.note, state: info.word, tone: st === "connected" || st === "local" ? "live" : info.lamp === "bad" ? "bad" : info.lamp === "warn" ? "warn" : "" },
          { route: "updates", icon: "i-updates", title: "Обновления", note: updateState, state: newer ? "новая" : "проверка", tone: updateTone },
          { route: "diagnostics", icon: "i-diagnostics", title: "Диагностика", note: broken ? count(broken, "звено", "звена", "звеньев") + " без подтверждения" : "все звенья на месте", state: broken ? "!" + broken : "ок", tone: broken ? "warn" : "ok" }
        ].forEach(function (item) {
          var card = el(doc, "a", "service-card");
          card.href = "#" + item.route;
          if (item.tone) card.setAttribute("data-tone", item.tone);
          var icon = el(doc, "span", "service-icon");
          var svg = doc.createElementNS(SVG, "svg");
          svg.setAttribute("viewBox", "0 0 24 24");
          svg.setAttribute("aria-hidden", "true");
          var use = doc.createElementNS(SVG, "use");
          use.setAttribute("href", "#" + item.icon);
          svg.appendChild(use);
          icon.appendChild(svg);
          var copy = el(doc, "span", "service-copy");
          add(copy, el(doc, "strong", "", item.title), el(doc, "small", "", item.note));
          var state = el(doc, "span", "service-state", item.state);
          var arrow = doc.createElementNS(SVG, "svg");
          arrow.setAttribute("class", "service-arrow");
          arrow.setAttribute("viewBox", "0 0 24 24");
          arrow.setAttribute("aria-hidden", "true");
          var arrowUse = doc.createElementNS(SVG, "use");
          arrowUse.setAttribute("href", "#i-arrow");
          arrow.appendChild(arrowUse);
          add(card, icon, copy, state, arrow);
          services.appendChild(card);
        });
      }
    }

    var catalog = this.$("overview-catalog");
    if (catalog) {
      var catalogKey = JSON.stringify([m.groups.length, m.boxes.length, bindings, m.k.catalog_at]);
      if (catalog.__r2oKey !== catalogKey) {
        catalog.__r2oKey = catalogKey;
        catalog.replaceChildren();
        var grid = el(doc, "dl", "catalog-grid");
        var catalogAt = parseTime(m.k.catalog_at);
        var catalogAge = catalogAt ? this.serverNow() - catalogAt : null;
        var catalogAgeText = catalogAge === null ? "—"
          : catalogAge < 45000 ? "сейчас"
            : catalogAge < 3600000 ? Math.max(1, Math.round(catalogAge / 60000)) + " мин"
              : Math.round(catalogAge / 3600000) + " ч";
        [
          ["Семейства", String(m.groups.length)],
          ["Коробки", String(m.boxes.length)],
          ["Цели", String(bindings)],
          ["Обновлён", catalogAgeText]
        ].forEach(function (item) {
          var cell = el(doc, "div", "catalog-cell");
          add(cell, el(doc, "dt", "", item[0]), el(doc, "dd", "", item[1]));
          grid.appendChild(cell);
        });
        var actions = el(doc, "div", "catalog-actions");
        [["families", "Семейства", String(m.groups.length)], ["boxes", "Коробки", String(m.boxes.length)]].forEach(function (item) {
          var link = el(doc, "a", "catalog-link");
          link.href = "#" + item[0];
          add(link, el(doc, "span", "", item[1]), el(doc, "span", "", item[2]));
          actions.appendChild(link);
        });
        catalog.append(grid, actions);
      }
    }

    var workload = this.$("workload-meta");
    if (workload) {
      var text = m.hunting ? m.hunting + " в работе" + (m.queued.length ? " · " + m.queued.length + " ждут" : "") : "очередь пуста";
      if (workload.textContent !== text) workload.textContent = text;
    }
    var tm = this.$("telegram-meta");
    if (tm) {
      var tgKey = JSON.stringify([st, info.word]);
      if (tm.__r2oKey !== tgKey) {
        tm.__r2oKey = tgKey;
        tm.replaceChildren();
        var chip = el(doc, "span", "meta-chip", info.word);
        chip.setAttribute("data-tone", st === "connected" || st === "local" ? "live" : info.lamp === "bad" ? "bad" : info.lamp === "warn" ? "warn" : "");
        tm.appendChild(chip);
      }
    }
  };

  App.prototype.serverNow = function () {
    var taken = this.status && parseTime(this.status.snapshot && this.status.snapshot.taken);
    return taken ? taken + (Date.now() - this.received) : Date.now();
  };

  var CONTROL_RESULT = {
    done: { tone: "ok", text: "Команда службы выполнена." },
    failed: { tone: "bad", text: "Команда службы завершилась ошибкой." },
    timeout: { tone: "bad", text: "Команда службы не завершилась вовремя и была прервана." }
  };

  App.prototype.render = function () {
    var m = model(this.status, this.received, Date.now());
    var cs = str(m.snap.control_state);
    if (this.lastControl === "running" && CONTROL_RESULT[cs]) {
      this.flash = { tone: CONTROL_RESULT[cs].tone, text: CONTROL_RESULT[cs].text, what: this.lastAction || "", at: Date.now() };
    }
    this.lastControl = cs;
    this.m = m;
    this.renderMast(m);
    this.renderNotice();
    this.renderNow(m);
    this.renderCatalog(false);
    this.renderTelegram(m);
    this.renderDiagnostics(m);
    this.renderOverview(m);
    this.renderNav(m);
    if (!this.arrived) {
      this.arrived = true;
      if (Motion.on()) {
        var d = this.doc;
        var rows = [].slice.call(d.querySelectorAll("#searches > li")).slice(0, 4);
        var cells = [].slice.call(d.querySelectorAll(".slot-cell"));
        var intro = Motion.g.timeline({ defaults: { ease: "power4.out", clearProps: "transform,opacity,visibility" } })
          .from("#now-title", { y: 22, autoAlpha: 0, duration: 0.45 })
          .from("#now-lede", { y: 10, autoAlpha: 0, duration: 0.35 }, "-=0.32");
        if (cells.length) intro.from(cells, { scale: 0.3, autoAlpha: 0, duration: 0.36, stagger: 0.045, ease: "back.out(2.4)" }, "-=0.38");
        if (rows.length) intro.from(rows, { y: 12, autoAlpha: 0, duration: 0.35, stagger: 0.05 }, "-=0.22");
      }
    }
  };

  /* ─── Мачта ─── */

  App.prototype.renderMast = function (m) {
    var doc = this.doc;
    var host = this.$("host");
    host.textContent = str(m.snap.panel_listen);
    var state = this.$("engine-state");
    var lamp = state.querySelector(".lamp");
    lamp.setAttribute("data-tone", m.lamp);
    var text = state.querySelector(".mast-state-text");
    /* Живой регион трогаем только при смене текста: иначе диктор повторяет его на каждом опросе. */
    var stateKey = m.state + "|" + m.stateDetail;
    if (text.__r2oKey !== stateKey) {
      text.__r2oKey = stateKey;
      text.replaceChildren(doc.createTextNode(m.state), el(doc, "small", "", m.stateDetail));
    }
    this.updateTitle();
    this.renderActions();
    var rail = this.$("rail-status");
    if (rail) {
      var railLamp = rail.querySelector(".lamp");
      if (railLamp) railLamp.setAttribute("data-tone", m.lamp);
      var railText = this.$("rail-status-text");
      if (railText && railText.textContent !== m.state) railText.textContent = m.state;
    }
  };

  App.prototype.renderActions = function () {
    var doc = this.doc, m = this.m;
    var box = this.$("engine-actions");
    if (!m) return;
    var snap = m.snap;
    var busy = snap.control_state === "running" || !!this.pending;
    var key = JSON.stringify([snap.controls_enabled, m.engine, busy, this.pending, this.armed, snap.mode]);
    if (box.__r2oKey === key) return;
    box.__r2oKey = key;
    var focused = doc.activeElement && box.contains(doc.activeElement) ? doc.activeElement.getAttribute("data-control") : null;
    var buttons = [];
    if (!snap.controls_enabled) {
      buttons.push(el(doc, "span", "tag", "Управление отключено в конфигурации"));
    } else {
      if (m.engine) {
        if (this.armed === "stop") {
          buttons.push(this.button("stop", "Остановить движок?", "stop", "confirm", busy));
          buttons.push(this.button("cancel", "Отмена", null, "ghost", false));
        } else {
          /* «Очистить подобранное» стоит там, где прежде была «Восстановить
             правила»: правила и без кнопки ставит сторож (S99r2o heal каждые
             60 с), а снять найденное замером руками было нечем. Вариант
             danger, и нажатие само ничего не делает — спрашивает диалог. */
          buttons.push(this.button("clear-found", "Очистить подобранное", "erase", "danger", busy, "Очистить"));
          buttons.push(this.button("restart", "Перезапустить", "restart", null, busy));
          buttons.push(this.button("stop", "Остановить", "stop", "danger", busy));
        }
      } else {
        buttons.push(this.button("start", "Запустить движок", "play", "primary", busy || snap.mode === "off"));
      }
    }
    var flipState = Motion.on() && Motion.Flip && box.children.length ? Motion.Flip.getState(box.children) : null;
    var oldIcons = {};
    for (var oi = 0; oi < box.children.length; oi++) {
      var op = box.children[oi].querySelector && box.children[oi].querySelector("svg path");
      if (op) oldIcons[box.children[oi].getAttribute("data-flip-id")] = op.getAttribute("d");
    }
    box.replaceChildren.apply(box, buttons);
    if (flipState) {
      /* Кнопки перетекают: «Остановить» ↔ «Остановить движок?», «стоп» ↔ «запуск». */
      Motion.track(Motion.Flip.from(flipState, {
        targets: box.children, duration: 0.25, ease: "power3.inOut", scale: false, simple: true,
        onEnter: function (els) { return Motion.g.fromTo(els, { autoAlpha: 0, scale: 0.85 }, { autoAlpha: 1, scale: 1, duration: 0.35, clearProps: "transform,opacity,visibility" }); }
      }));
      if (global.MorphSVGPlugin) {
        for (var ni = 0; ni < box.children.length; ni++) {
          var np = box.children[ni].querySelector && box.children[ni].querySelector("svg path");
          var was = oldIcons[box.children[ni].getAttribute("data-flip-id")];
          if (np && was && was !== np.getAttribute("d")) Motion.g.from(np, { morphSVG: was, duration: 0.3, ease: "power2.inOut" });
        }
      }
    }
    if (focused) {
      var again = box.querySelector('[data-control="' + focused + '"]') || box.querySelector("button");
      if (again) again.focus();
    }
  };

  App.prototype.button = function (action, label, iconName, variant, disabled, shortLabel) {
    var self = this, doc = this.doc;
    var b = el(doc, "button", "btn");
    b.type = "button";
    b.setAttribute("data-control", action);
    b.setAttribute("data-flip-id", action === "start" || action === "stop" ? "power" : action);
    if (variant) b.setAttribute("data-variant", variant);
    if (this.pending === action) b.setAttribute("data-busy", "true");
    if (iconName) add(b, icon(doc, this.pending === action ? "restart" : iconName));
    if (shortLabel) {
      add(b, el(doc, "span", "btn-label-long", label));
      b.setAttribute("aria-label", label);
    } else {
      add(b, el(doc, "span", "", label));
    }
    b.setAttribute("aria-label", label);
    b.title = label;
    if (disabled) b.disabled = true;
    b.addEventListener("click", function () { self.act(action); });
    return b;
  };

  var ENDPOINTS = {
    start: "start", stop: "stop", restart: "restart", "clear-found": "clear-found",
    "telegram-enable": "telegram-enable", "telegram-disable": "telegram-disable",
    "telegram-check": "telegram-check"
  };

  /* ОПЕРАЦИИ, КОТОРЫЕ СПРАШИВАЮТ ДИАЛОГОМ.
     Второго нажатия кнопки (приём «Остановить движок?») здесь мало: то
     нажатие защищает от промаха, а здесь надо сказать, ЧТО именно исчезнет и
     что обратно это не вернуть. В подпись кнопки такой текст не влезает. */
  var CONFIRM = {
    "clear-found": {
      title: "Очистить подобранное?",
      text: "Это сотрёт всё, что движок подобрал замером: подтверждённые планы, "
          + "привязки имён к адресам и каталог коробок. Восстановить нельзя — "
          + "подбор начнётся с нуля, и на каждый сайт его придётся пройти заново. "
          + "Точно очищаем?",
      yes: "Очистить"
    }
  };

  /* Спрашивает и зовёт done() только на согласие. Нативный <dialog> даёт Esc,
     ::backdrop и ловушку фокуса; где его нет — обычный confirm(), потому что
     необратимая операция обязана спросить ХОТЬ ЧЕМ-ТО, а не пройти молча. */
  App.prototype.ask = function (what, done) {
    var doc = this.doc, dlg = this.$("ask");
    if (!dlg || typeof dlg.showModal !== "function") {
      if (this.win.confirm(what.title + "\n\n" + what.text)) done();
      return;
    }
    var title = this.$("ask-title"), text = this.$("ask-text");
    if (title) title.textContent = what.title;
    if (text) text.textContent = what.text;
    var yes = dlg.querySelector('[data-ask="yes"]');
    var no = dlg.querySelector('[data-ask="no"]');
    if (yes) yes.replaceChildren(doc.createTextNode(what.yes));
    var agreed = false;
    function close() { agreed = false; dlg.close(); }
    function accept() { agreed = true; dlg.close(); }
    /* Слушатели снимаются на закрытии: диалог один на все операции, и
       оставленный слушатель применил бы прошлое согласие к новой. */
    function onClose() {
      if (yes) yes.removeEventListener("click", accept);
      if (no) no.removeEventListener("click", close);
      dlg.removeEventListener("close", onClose);
      if (agreed) done();
    }
    if (yes) yes.addEventListener("click", accept);
    if (no) no.addEventListener("click", close);
    dlg.addEventListener("close", onClose);
    dlg.showModal();
    if (no && no.focus) no.focus();   /* фокус на отказе, не на необратимом */
  };

  function normalizeWorkerInput(value) {
    var domain = str(value).trim().toLowerCase();
    if (!domain || domain.length > 253) return null;
    var labels = domain.split("."), tld = labels[labels.length - 1];
    if (labels.length < 2 || tld.length < 2 || !/[a-z]/.test(tld)) return null;
    for (var i = 0; i < labels.length; i++) {
      if (labels[i].length < 1 || labels[i].length > 63 ||
          !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(labels[i])) return null;
    }
    return domain;
  }

  App.prototype.renderWorkerDialog = function () {
    var dialog = this.workerDialog;
    if (!dialog) return;
    var listNode = dialog.querySelector("[data-worker-list]");
    var input = dialog.querySelector("[data-worker-input]");
    var addButton = dialog.querySelector("[data-worker-add]");
    var saveButton = dialog.querySelector("[data-worker-save]");
    var note = dialog.querySelector("[data-worker-note]");
    var editable = !!(this.m && this.m.snap.controls_enabled) && !this.pending;
    input.disabled = !editable || this.workerDomains.length >= 8;
    addButton.disabled = !editable || this.workerDomains.length >= 8;
    saveButton.disabled = !editable;
    listNode.replaceChildren();
    if (!this.workerDomains.length) {
      listNode.appendChild(el(this.doc, "li", "tg-worker-empty", "Пока нет добавленных доменов"));
    }
    var self = this;
    this.workerDomains.forEach(function (domain, index) {
      var row = el(self.doc, "li", "tg-worker-row");
      var name = el(self.doc, "span", "", domain);
      var remove = el(self.doc, "button", "tg-worker-remove", "Удалить");
      remove.type = "button";
      remove.disabled = !editable;
      remove.setAttribute("aria-label", "Удалить " + domain);
      remove.addEventListener("click", function () {
        self.workerDomains.splice(index, 1);
        self.renderWorkerDialog();
      });
      row.append(name, remove);
      listNode.appendChild(row);
    });
    if (note) {
      note.textContent = this.m && !this.m.snap.controls_enabled
        ? "Управление отключено в конфигурации. Список доступен только для просмотра."
        : this.workerDomains.length >= 8 ? "Добавлено 8 из 8 доменов." : "Добавьте hostname Worker без схемы и пути.";
    }
  };

  App.prototype.openTelegramWorkers = function () {
    var self = this, doc = this.doc;
    if (this.pending) return;
    if (!this.workerDialog) {
      var dialog = this.workerDialog = el(doc, "dialog", "tg-worker-dialog");
      dialog.setAttribute("aria-labelledby", "tg-worker-title");
      var heading = el(doc, "h2", "", "Мои Workers");
      heading.id = "tg-worker-title";
      var intro = el(doc, "p", "tg-worker-intro", "Добавьте до 8 доменов Cloudflare Worker. Настройки сохранятся и перезапустят только C11.");
      var listNode = el(doc, "ul", "tg-worker-list");
      listNode.setAttribute("data-worker-list", "");
      var field = el(doc, "label", "tg-worker-field", "Домен Worker");
      var input = el(doc, "input", "");
      input.type = "text";
      input.autocomplete = "url";
      input.spellcheck = false;
      input.placeholder = "my-worker.example.com";
      input.setAttribute("data-worker-input", "");
      field.appendChild(input);
      var addButton = el(doc, "button", "btn", "Добавить домен");
      addButton.type = "button";
      addButton.setAttribute("data-worker-add", "");
      var note = el(doc, "p", "tg-worker-note", "");
      note.setAttribute("data-worker-note", "");
      var message = el(doc, "p", "tg-worker-message", "");
      message.setAttribute("aria-live", "polite");
      var cancel = el(doc, "button", "btn", "Отмена");
      cancel.type = "button";
      var save = el(doc, "button", "btn", "Сохранить");
      save.type = "button";
      save.setAttribute("data-variant", "primary");
      save.setAttribute("data-worker-save", "");
      var footer = el(doc, "div", "tg-worker-footer");
      footer.append(cancel, save);
      dialog.append(heading, intro, listNode, field, addButton, note, message, footer);
      doc.body.appendChild(dialog);
      function addDomain() {
        var domain = normalizeWorkerInput(input.value);
        if (!domain) { message.textContent = "Введите корректный домен, например my-worker.example.com."; return; }
        if (self.workerDomains.indexOf(domain) >= 0) { message.textContent = "Этот домен уже добавлен."; return; }
        if (self.workerDomains.length >= 8) { message.textContent = "Можно добавить не больше 8 доменов."; return; }
        self.workerDomains.push(domain);
        input.value = "";
        message.textContent = "";
        self.renderWorkerDialog();
        input.focus();
      }
      addButton.addEventListener("click", addDomain);
      input.addEventListener("keydown", function (event) {
        if (event.key === "Enter") { event.preventDefault(); addDomain(); }
      });
      cancel.addEventListener("click", function () { dialog.close(); });
      save.addEventListener("click", function () { self.saveTelegramWorkers(message); });
    }
    var dialog = this.workerDialog;
    var message = dialog.querySelector(".tg-worker-message");
    message.textContent = "Загружаем список…";
    if (typeof dialog.showModal === "function") dialog.showModal();
    this.win.fetch("/api/telegram/workers", { cache: "no-store" })
      .then(function (reply) {
        return reply.json().then(function (body) {
          if (!reply.ok || !Array.isArray(body.domains)) throw new Error(body.message || "Не удалось загрузить домены");
          self.workerDomains = body.domains.slice(0, 8);
          message.textContent = "";
          self.renderWorkerDialog();
        });
      })
      .catch(function (error) { message.textContent = str(error && error.message) || "Не удалось загрузить список Workers."; });
  };

  App.prototype.saveTelegramWorkers = function (message) {
    var self = this;
    if (this.pending || !(this.m && this.m.snap.controls_enabled)) return;
    this.pending = "telegram-workers";
    this.renderTelegram(this.m, true);
    this.renderWorkerDialog();
    this.win.fetch("/api/telegram/workers", {
      method: "POST", cache: "no-store", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domains: this.workerDomains })
    }).then(function (reply) {
      return reply.json().catch(function () { return {}; }).then(function (body) {
        if (!reply.ok) throw new Error(str(body.message) || "Не удалось сохранить Workers.");
        self.workerDialog.close();
        self.flash = { tone: "info", text: str(body.message) || "Настройки Workers сохранены.", at: Date.now() };
      });
    }).catch(function (error) {
      message.textContent = str(error && error.message) || "Не удалось сохранить список Workers.";
    }).then(function () {
      self.pending = null;
      self.renderTelegram(self.m, true);
      self.renderWorkerDialog();
      self.renderNotice();
      self.poll();
      self.win.setTimeout(function () { self.poll(); }, 800);
    });
  };

  /* Неудавшаяся команда — короткое покачивание её кнопки рядом с текстом ошибки. */
  App.prototype.shake = function (action) {
    if (!Motion.on()) return;
    var b = this.doc.querySelector('[data-control="' + action + '"]');
    if (b) Motion.g.fromTo(b, { x: 0 }, { x: 7, duration: 0.6, ease: global.CustomWiggle ? "r2oShake" : "power1.inOut", clearProps: "transform" });
  };

  App.prototype.act = function (action, confirmed) {
    var self = this;
    if (action === "telegram-workers") { this.openTelegramWorkers(); return; }
    if (action === "cancel") { this.armed = null; this.renderActions(); return; }
    if (CONFIRM[action] && !confirmed) {
      if (this.pending) return;
      this.ask(CONFIRM[action], function () { self.act(action, true); });
      return;
    }
    if (action === "stop" && this.armed !== "stop") {
      this.armed = "stop";
      this.renderActions();
      this.win.setTimeout(function () { if (self.armed === "stop") { self.armed = null; self.renderActions(); } }, 6000);
      return;
    }
    this.armed = null;
    if (!ENDPOINTS[action] || this.pending) return;
    this.pending = action;
    this.renderActions();
    this.renderTelegram(this.m, true);
    this.win.fetch("/api/control/" + ENDPOINTS[action], { method: "POST", cache: "no-store" })
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (body) {
          if (body.action) self.lastAction = str(body.action);
          if (!r.ok) self.shake(action);
          self.flash = {
            tone: r.ok ? "info" : "bad",
            text: str(body.message) || (r.ok ? "Команда принята" : "Команда не выполнена (HTTP " + r.status + ")"),
            what: str(body.action),
            at: Date.now()
          };
        });
      })
      .catch(function () {
        self.shake(action);
        self.flash = { tone: "bad", text: "Панель не ответила на команду. Состояние ниже — последнее полученное.", at: Date.now() };
      })
      .then(function () {
        self.pending = null;
        self.renderNotice();
        self.poll();
        self.win.setTimeout(function () { self.poll(); }, 800);
      });
  };

  /* ─── Уведомление ─── */

  App.prototype.renderNotice = function () {
    var doc = this.doc, n = this.$("notice");
    var parts = null, tone = null;
    var now = Date.now();
    var stale = this.lastOk && now - this.lastOk > STALE_MS;
    doc.body.setAttribute("data-stale", String(!!(this.failed && (stale || !this.lastOk))));
    if (this.failed && !this.lastOk) {
      tone = "bad"; parts = [el(doc, "b", "", "Панель не получает состояние."), " Повторяем запрос каждые две секунды."];
    } else if (this.failed && stale) {
      tone = "bad";
      parts = [el(doc, "b", "", "Нет ответа от панели."), " Показан снимок, полученный " + ago(now - this.lastOk) + "."];
    } else if (this.m && this.m.snap.control_state === "running" && !(this.flash && now - this.flash.at < 1500)) {
      tone = "info"; parts = [el(doc, "b", "", "Выполняется команда службы."), " Управление станет доступно, когда она завершится."];
    } else if (this.flash && now - this.flash.at < 8000) {
      tone = this.flash.tone;
      parts = [this.flash.what ? el(doc, "b", "", this.flash.what + ".") : null, " " + this.flash.text];
    } else if (this.m && this.m.snap.preview) {
      tone = "info"; parts = [el(doc, "b", "", "Демонстрационные данные."), " Это локальный стенд, а не роутер."];
    } else if (this.m && this.m.engine && !this.m.fresh) {
      tone = "warn"; parts = [el(doc, "b", "", "Снимок движка устарел."), " Движок давно не обновлял состояние; цифры ниже могут быть не текущими."];
    }
    if (!parts) {
      if (n.hidden || n.__closing) return;
      if (Motion.on()) {
        n.__closing = true;
        Motion.g.to(n, { height: 0, paddingTop: 0, paddingBottom: 0, autoAlpha: 0, duration: 0.3, ease: "power2.in", onComplete: function () {
          n.__closing = false; n.hidden = true; n.replaceChildren(); Motion.g.set(n, { clearProps: "all" });
        } });
      } else { n.hidden = true; n.replaceChildren(); }
      return;
    }
    var key = tone + "|" + parts.map(function (x) { return x && x.textContent !== undefined ? x.textContent : String(x); }).join("");
    if (key === n.__r2oKey && !n.hidden && !n.__closing) return;
    n.__r2oKey = key;
    var appearing = n.hidden || n.__closing;
    if (n.__closing) { Motion.g.killTweensOf(n); n.__closing = false; Motion.g.set(n, { clearProps: "all" }); }
    n.hidden = false;
    n.setAttribute("data-tone", tone);
    n.replaceChildren();
    add.apply(null, [n].concat(parts));
    if (appearing && Motion.on()) Motion.g.from(n, { height: 0, paddingTop: 0, paddingBottom: 0, autoAlpha: 0, duration: 0.28, clearProps: "all" });
  };

  /* ─── Сейчас ─── */

  App.prototype.renderNow = function (m) {
    var doc = this.doc;
    var title = this.$("now-title");
    var h = JSON.stringify(m.headline);
    if (title.__r2oKey !== h) {
      var prev = title.__r2oHeadline;
      title.__r2oKey = h;
      title.__r2oHeadline = m.headline;
      var apply = function () { title.replaceChildren(doc.createTextNode(m.headline[0]), el(doc, "em", "", m.headline[1])); };
      var from = prev && /^(\d+) /.exec(prev[1]), to = /^(\d+) /.exec(m.headline[1]);
      if (!prev || !Motion.on()) {
        apply();
      } else if (from && to && prev[0] === m.headline[0]) {
        /* Тот же заголовок, другое число: число прокручивается. */
        apply();
        var em = title.lastChild, n = { v: +from[1] };
        Motion.g.to(n, { v: +to[1], duration: 0.4, ease: "power2.out", onUpdate: function () {
          var v = Math.round(n.v);
          em.textContent = count(v, "поиск", "поиска", "поисков");
        } });
        Motion.g.fromTo(em, { y: -5 }, { y: 0, duration: 0.32, ease: "back.out(3)" });
      } else {
        /* Новая фраза собирается по буквам; разбиение снимается по окончании. */
        Motion.g.timeline()
          .to(title, { y: -14, autoAlpha: 0, duration: 0.18, ease: "power2.in" })
          .add(function () {
            apply();
            Motion.g.set(title, { y: 0, autoAlpha: 1 });
            if (!global.SplitText) { Motion.g.from(title, { y: 16, autoAlpha: 0, duration: 0.34, clearProps: "all" }); return; }
            var split = new global.SplitText(title, { type: "words,chars" });
            Motion.g.from(split.chars, { yPercent: 70, autoAlpha: 0, rotation: 4, duration: 0.4, stagger: 0.014, ease: "power4.out",
              onComplete: function () { split.revert(); Motion.g.set(title, { clearProps: "all" }); } });
          });
      }
    }
    title.setAttribute("data-tone", m.tone);
    this.$("now-lede").textContent = m.lede;
    var panel = this.$("status-panel");
    if (panel) panel.setAttribute("data-tone", m.tone);
    var statusLamp = this.$("status-lamp");
    if (statusLamp) statusLamp.setAttribute("data-tone", m.lamp);
    var statusState = this.$("status-state");
    if (statusState && statusState.textContent !== m.state) statusState.textContent = m.state;

    var slots = this.$("slots");
    var meas = m.k.measurements;
    var wasActive = slots.__r2oActive;
    var rebuilt = section(slots, JSON.stringify([m.linked, meas, m.k.targets, m.k.confirms, m.k.probes_used, m.k.client_unfit, m.groups.length, m.boxes.length]), function () {
      var out = [];
      if (m.linked && meas && num(meas.limit)) {
        var sv = slotsView(meas);
        var row = el(doc, "div", "slot-row");
        row.title = sv.note;
        if (sv.kind === "cells") {
          var cells = el(doc, "div", "slot-cells");
          cells.setAttribute("aria-hidden", "true");
          for (var i = 0; i < sv.limit; i++) {
            var c = el(doc, "span", "slot-cell");
            c.setAttribute("data-on", String(i < sv.active));
            cells.appendChild(c);
          }
          row.appendChild(cells);
        } else {
          /* Десятки замеров клетками не нарисовать честно — шкала с долей занятых. */
          var bar = el(doc, "span", "slot-bar");
          bar.setAttribute("aria-hidden", "true");
          var fill = el(doc, "span", "slot-bar-fill");
          fill.style.setProperty("--share", String(sv.active / sv.limit));
          bar.appendChild(fill);
          row.appendChild(bar);
        }
        add(row, el(doc, "span", "", "Замеры: " + sv.active + " из " + sv.limit +
          (sv.queued ? ", в очереди " + sv.queued : "")), el(doc, "small", "slot-note", sv.short));
        out.push(row);
        if (num(meas.free_pct) !== null) {
          out.push(el(doc, "span", "", "Свободно процессора " + meas.free_pct + "%" +
            (num(meas.cores) ? " на " + count(meas.cores, "ядре", "ядрах", "ядрах") : "")));
        }
      }
      if (m.linked) {
        var facts = el(doc, "span", "");
        add(facts,
          el(doc, "b", "", String(num(m.k.confirms) || 0)), " " + plural(num(m.k.confirms) || 0, "подтверждение", "подтверждения", "подтверждений") + ", ",
          el(doc, "b", "", String(num(m.k.probes_used) || 0)), " " + plural(num(m.k.probes_used) || 0, "зонд", "зонда", "зондов") + " за работу движка");
        out.push(facts);
        if (num(m.k.client_unfit)) {
          var unfit = el(doc, "span", "");
          add(unfit, tag(doc, "план не подошёл клиенту: " + m.k.client_unfit, "warn"));
          out.push(unfit);
        }
      }
      return out;
    });
    var nowActive = meas && num(meas.active) !== null ? meas.active : null;
    if (rebuilt && Motion.on() && wasActive !== undefined && nowActive !== null && nowActive !== wasActive) {
      var cellsNow = slots.querySelectorAll(".slot-cell");
      var lit = [], dim = [];
      for (var ci = 0; ci < cellsNow.length; ci++) {
        if (ci >= Math.min(wasActive || 0, nowActive) && ci < Math.max(wasActive || 0, nowActive)) (ci < nowActive ? lit : dim).push(cellsNow[ci]);
      }
      if (lit.length) Motion.g.from(lit, { scale: 0.2, autoAlpha: 0, duration: 0.3, stagger: 0.05, ease: "back.out(2.4)", clearProps: "all" });
      if (dim.length) {
        var sig = global.getComputedStyle(doc.documentElement).getPropertyValue("--acc").trim() || "#7fd0d4";
        Motion.g.from(dim, { backgroundColor: sig, duration: 0.35, ease: "power2.out", clearProps: "all" });
      }
    }
    slots.__r2oActive = nowActive === null ? undefined : nowActive;

    this.renderSearches(m);
  };

  App.prototype.renderSearches = function (m) {
    var doc = this.doc, self = this;
    var listNode = this.$("searches");
    if (!m.linked || !m.engine) {
      section(listNode, "absent:" + m.engine + ":" + m.linked, function () {
        var li = el(doc, "li", "quiet");
        add(li, el(doc, "b", "", "Поиски не измеряются."), m.engine
          ? " Контроллер не подключён к датапату, поэтому список поисков недоступен."
          : " Движок остановлен.");
        return [li];
      });
      return;
    }
    if (!m.searches.length) {
      section(listNode, "none", function () {
        var li = el(doc, "li", "quiet");
        add(li, el(doc, "b", "", "Рабочий прямой трафик подбор не запускает"),
          " — он начинается только после подтверждённой блокировки, а найденное решение сохраняется в каталоге ниже.");
        return [li];
      });
      return;
    }
    if (listNode.__r2oKey === "none" || (listNode.__r2oKey && listNode.__r2oKey.indexOf("absent:") === 0)) {
      listNode.replaceChildren();
    }
    var firstLive = listNode.__r2oKey !== "live";
    listNode.__r2oKey = "live";
    var animate = Motion.on() && Motion.Flip;
    var stable = [];
    for (var si = 0; si < listNode.children.length; si++) if (!listNode.children[si].__leaving) stable.push(listNode.children[si]);
    var wantKeys = m.running.map(function (x) { return JSON.stringify([x.target, x.family, x.transport, x.ip, x.port]); });
    if (m.queued.length) wantKeys.push("queue");
    var haveKeys = stable.map(function (r) { return r.__r2oKey; });
    var flipState = animate && stable.length && wantKeys.join("\n") !== haveKeys.join("\n") ? Motion.Flip.getState(stable) : null;
    if (flipState) stable.forEach(function (r) { r.__oldTop = r.getBoundingClientRect().top; });
    var entered = [], moved = false;

    var keep = {};
    m.running.forEach(function (s, index) {
      var key = JSON.stringify([s.target, s.family, s.transport, s.ip, s.port]);
      keep[key] = true;
      var row = null;
      for (var i = 0; i < listNode.children.length; i++) {
        if (listNode.children[i].__r2oKey === key) { row = listNode.children[i]; break; }
      }
      if (!row) {
        row = self.searchRow(s);
        row.__r2oKey = key;
        entered.push(row);
      }
      self.updateSearch(row, s);
      if (listNode.children[index] !== row) { listNode.insertBefore(row, listNode.children[index] || null); moved = true; }
    });
    var queue = null;
    for (var q = 0; q < listNode.children.length; q++) if (listNode.children[q].__r2oKey === "queue") queue = listNode.children[q];
    if (m.queued.length) {
      if (!queue) { queue = el(doc, "li", "queue"); queue.__r2oKey = "queue"; }
      keep.queue = true;
      this.updateQueue(queue, m.queued);
      if (listNode.lastChild !== queue) { listNode.appendChild(queue); moved = true; }
    }
    var leaving = [];
    for (var j = listNode.children.length - 1; j >= 0; j--) {
      var gone = listNode.children[j];
      if (keep[gone.__r2oKey] || gone.__leaving) continue;
      if (animate) leaving.push(gone); else listNode.removeChild(gone);
    }
    if (!animate) return;
    if (!entered.length && !leaving.length && !moved) return;
    /* Ушедшая строка уезжает и гаснет; остальные плавно занимают её место. */
    leaving.forEach(function (row) {
      row.__leaving = true;
      var done = row.getAttribute("data-done") === "true";
      Motion.g.timeline({ onComplete: function () {
        var rest = [];
        for (var k = 0; k < listNode.children.length; k++) if (listNode.children[k] !== row && !listNode.children[k].__leaving) rest.push(listNode.children[k]);
        var st = rest.length ? Motion.Flip.getState(rest) : null;
        if (row.parentNode) row.parentNode.removeChild(row);
        if (st) Motion.track(Motion.Flip.from(st, { duration: 0.3, ease: "power3.inOut", scale: true, simple: true }));
      } })
        .to(row, { x: done ? 0 : 36, y: done ? 18 : 0, autoAlpha: 0, duration: 0.22, ease: "power2.in" });
    });
    if (flipState) {
      /* Переставляемые строки «приподнимаются» и проезжают поверх соседних, не сквозь них. */
      var movers = stable.filter(function (r) { return !r.__leaving; });
      movers.forEach(function (r) { r.__goesUp = r.getBoundingClientRect().top < r.__oldTop - 1; });
      Motion.track(Motion.Flip.from(flipState, {
        duration: 0.34, ease: "power3.inOut", scale: true, simple: true, targets: movers,
        onStart: function () { movers.forEach(function (r) { r.classList.add("is-moving"); r.style.zIndex = r.__goesUp ? 3 : 2; }); },
        onComplete: function () { movers.forEach(function (r) { r.classList.remove("is-moving"); r.style.zIndex = ""; }); }
      }));
    }
    if (entered.length && !firstLive) {
      Motion.g.fromTo(entered, { y: 18, autoAlpha: 0 }, { y: 0, autoAlpha: 1, duration: 0.34, stagger: 0.05, ease: "power4.out", clearProps: "transform,opacity,visibility" });
    }
  };

  App.prototype.updateQueue = function (li, queued) {
    var doc = this.doc;
    var key = JSON.stringify(queued.map(function (s) { return [s.target, s.family, s.transport, s.ip, s.port, s.since]; }));
    if (li.__r2oData !== key) {
      li.__r2oData = key;
      var head = el(doc, "p", "queue-head");
      add(head, el(doc, "b", "", "Ждут свободного слота замера: " + queued.length),
        " — замеры идут не больше, чем позволяет свободный процессор.");
      var ul = el(doc, "ul", "queue-list");
      queued.forEach(function (s) {
        var row = el(doc, "li"), wait = el(doc, "span", "queue-wait");
        wait.__since = parseTime(s.since);
        add(row, el(doc, "span", "queue-target", targetLabel(s.target)),
          tag(doc, shapeLabel(s.shape, s.transport)), tag(doc, familyLabel(s.family)), wait);
        ul.appendChild(row);
      });
      li.replaceChildren(head, ul);
    }
    var waits = li.querySelectorAll(".queue-wait"), now = this.serverNow();
    for (var i = 0; i < waits.length; i++) waits[i].textContent = waits[i].__since ? "ждёт " + clock(now - waits[i].__since) : "";
  };

  function searchArc(cx, cy, radius, start, end) {
    var rad = function (deg) { return (deg - 90) * Math.PI / 180; };
    var sx = cx + radius * Math.cos(rad(start)), sy = cy + radius * Math.sin(rad(start));
    var ex = cx + radius * Math.cos(rad(end)), ey = cy + radius * Math.sin(rad(end));
    var large = Math.abs(end - start) > 180 ? 1 : 0;
    return "M" + sx.toFixed(2) + " " + sy.toFixed(2) + " A" + radius + " " + radius + " 0 " + large + " 1 " + ex.toFixed(2) + " " + ey.toFixed(2);
  }

  /* Прибор подбора: семь сегментов, один центральный знак этапа и живой
     пунктир только на текущем сегменте. Движение показывает, где именно
     идёт работа, а не украшает карточку. */
  function searchVisual(doc) {
    var wrap = el(doc, "div", "search-visual");
    wrap.setAttribute("aria-hidden", "true");
    var svg = svgEl(doc, "svg", { viewBox: "0 0 64 64" }, "probe-dial");
    var segments = svgEl(doc, "g", {}, "probe-segments");
    var segmentPaths = [];
    for (var index = 0; index < 7; index += 1) {
      var start = index * (360 / 7) + 3.2;
      var end = (index + 1) * (360 / 7) - 3.2;
      var path = searchArc(32, 32, 25, start, end);
      segmentPaths.push(path);
      var segment = svgEl(doc, "path", { d: path }, "probe-segment");
      segment.setAttribute("data-stage", String(index));
      segments.appendChild(segment);
    }
    svg.appendChild(segments);
    var sweep = svgEl(doc, "g", {}, "probe-sweep");
    sweep.appendChild(svgEl(doc, "path", { d: "M32 32 L32 7 A25 25 0 0 1 48 15 Z" }));
    svg.appendChild(sweep);
    var glyphs = svgEl(doc, "g", {}, "probe-glyphs");
    TRACK_ICONS.forEach(function (d, index) {
      var group = svgEl(doc, "g", {}, "probe-glyph");
      group.setAttribute("data-glyph", String(index));
      group.appendChild(svgEl(doc, "path", { d: d, transform: "translate(22.8 22.8) scale(1.15)" }));
      glyphs.appendChild(group);
    });
    var voice = svgEl(doc, "g", {}, "probe-glyph");
    voice.setAttribute("data-glyph", "voice");
    voice.appendChild(svgEl(doc, "path", { d: VOICE_ICONS[0], transform: "translate(22.8 22.8) scale(1.15)" }));
    glyphs.appendChild(voice);
    svg.appendChild(glyphs);
    var pulse = svgEl(doc, "circle", { cx: "32", cy: "32", r: "24" }, "probe-pulse");
    svg.appendChild(pulse);
    var code = el(doc, "span", "search-stage-code", "—");
    wrap.append(svg, code);
    wrap.__code = code;
    wrap.__segments = segments;
    wrap.__segmentPaths = segmentPaths;
    wrap.__glyphs = glyphs;
    wrap.__pulse = pulse;
    return wrap;
  }

  App.prototype.searchRow = function (s) {
    var doc = this.doc;
    var li = el(doc, "li", "search");
    li.__parts = {
      visual: searchVisual(doc),
      target: el(doc, "h2", "search-target"),
      meta: el(doc, "div", "search-meta"),
      clock: el(doc, "div", "search-clock"),
      phase: el(doc, "p", "search-phase"),
      question: el(doc, "p", "search-question"),
      plan: el(doc, "details", "search-plan-details"),
      planSummary: el(doc, "span", "search-plan-summary"),
      planBody: el(doc, "p", "search-plan-body"),
      track: el(doc, "div", "track"),
      trackNote: el(doc, "p", "track-note")
    };
    li.__parts.plan.hidden = true;
    var planHead = el(doc, "summary");
    planHead.appendChild(li.__parts.planSummary);
    add(li.__parts.plan, planHead, li.__parts.planBody);
    li.__parts.track.setAttribute("aria-hidden", "true");
    li.__parts.fill = el(doc, "span", "track-fill");
    li.__parts.puck = el(doc, "span", "track-puck");
    li.__parts.sweep = el(doc, "span", "search-sweep");
    li.__parts.sweepInner = el(doc, "span", "");
    li.__parts.sweep.appendChild(li.__parts.sweepInner);
    li.__parts.question.hidden = true;
    add(li, li.__parts.visual, li.__parts.target, li.__parts.clock, li.__parts.meta, li.__parts.phase, li.__parts.question, li.__parts.plan, li.__parts.sweep, li.__parts.track, li.__parts.trackNote);
    void s;
    return li;
  };

  App.prototype.updateSearch = function (li, s) {
    var doc = this.doc, p = li.__parts;
    p.target.textContent = targetLabel(s.target);
    var metaKey = JSON.stringify([s.shape, s.transport, s.family, s.ip, s.port, s.source, s.attempts, s.probes]);
    if (p.meta.__r2oKey !== metaKey) {
      p.meta.__r2oKey = metaKey;
      var addr = s.ip ? (s.family === 6 ? "[" + s.ip + "]" : s.ip) + (s.port ? ":" + s.port : "") : "";
      p.meta.replaceChildren();
      add(p.meta,
        tag(doc, shapeLabel(s.shape, s.transport)),
        tag(doc, familyLabel(s.family)),
        addr ? el(doc, "span", "mono", addr) : null,
        s.source ? el(doc, "span", "", s.source) : null);
    }
    var phase = str(s.phase) || "этап не указан";
    li.__since = parseTime(s.since);
    var counters = [];
    if (num(s.attempts)) counters.push(count(s.attempts, "план", "плана", "планов"));
    if (num(s.probes)) counters.push(count(s.probes, "зонд", "зонда", "зондов"));
    li.__counters = counters.join(" · ");
    this.updateClock(li);

    var phaseText = phase.charAt(0).toUpperCase() + phase.slice(1);
    if (p.phase.textContent !== phaseText) {
      if (p.phase.textContent && Motion.on()) {
        Motion.g.timeline()
          .to(p.phase, { y: -8, autoAlpha: 0, duration: 0.16, ease: "power2.in" })
          .add(function () { p.phase.textContent = phaseText; })
          .fromTo(p.phase, { y: 8, autoAlpha: 0 }, { y: 0, autoAlpha: 1, duration: 0.3, ease: "power3.out", clearProps: "transform,opacity,visibility" });
      } else {
        p.phase.textContent = phaseText;
      }
    }
    var candidate = str(s.candidate);
    p.plan.hidden = !candidate;
    if (candidate) {
      var gist = candidateGist(candidate);
      if (p.planSummary.textContent !== gist) p.planSummary.textContent = gist;
      if (p.planSummary.title !== candidate) p.planSummary.title = candidate;
      if (p.planBody.textContent !== candidate) p.planBody.textContent = candidate;
      var planHead = p.plan.querySelector("summary");
      if (planHead && planHead.getAttribute("aria-label") !== "План: " + gist) planHead.setAttribute("aria-label", "План: " + gist);
    }
    var classifying = s.phase === TRACK[2].phases[0] && !!str(s.question);
    p.question.hidden = !classifying;
    var qText = classifying ? "Вопрос коробке: " + str(s.question) : "";
    if (p.question.textContent !== qText) p.question.textContent = qText;
    var tr = trackFor(s.phase);
    var stageKey = tr ? (tr.voice ? "voice" : String(tr.at)) : "idle";
    var oldStage = li.__stage;
    li.__stage = stageKey;
    li.setAttribute("data-stage", stageKey);
    li.setAttribute("data-voice", String(!!tr && tr.voice));
    if (p.visual && p.visual.__code) {
      var stageCode = tr ? (tr.voice ? "голос" : ("0" + (tr.at + 1)).slice(-2) + "/" + ("0" + tr.steps.length).slice(-2)) : "—";
      var codeChanged = p.visual.__code.textContent !== stageCode;
      if (codeChanged) p.visual.__code.textContent = stageCode;
      var visualStage = tr ? tr.at : 0;
      var speeds = ["4.5s", "4s", "2.8s", "4s", "3.4s", "2.2s", "0s"];
      p.visual.style.setProperty("--probe-speed", tr && !tr.voice ? (speeds[tr.at] || "3.4s") : "3s");
      var segments = p.visual.__segments.children;
      for (var si = 0; si < segments.length; si += 1) {
        segments[si].setAttribute("data-state", si < visualStage ? "past" : si === visualStage ? "now" : "future");
      }
      var glyphs = p.visual.__glyphs.children;
      for (var gi = 0; gi < glyphs.length; gi += 1) {
        var on = glyphs[gi].getAttribute("data-glyph") === stageKey;
        glyphs[gi].classList.toggle("is-on", on);
      }
      if (oldStage !== undefined && oldStage !== stageKey && Motion.on()) {
        Motion.g.fromTo(p.visual.__pulse, { scale: .62, opacity: .5 }, {
          scale: 1.55, opacity: 0, duration: 0.8, ease: "power2.out", svgOrigin: "32 32", clearProps: "opacity,transform"
        });
        if (codeChanged) Motion.g.fromTo(p.visual.__code, { y: 2, opacity: 0 }, { y: 0, opacity: 1, duration: 0.24, ease: "power2.out", clearProps: "transform,opacity" });
        var width = li.getBoundingClientRect().width || 640;
        Motion.g.killTweensOf(p.sweepInner);
        Motion.g.fromTo(p.sweepInner, { x: -width * 0.35, opacity: 0 }, { x: width * 0.1, opacity: .7, duration: 0.2, ease: "power2.out" })
          .to(p.sweepInner, { x: width * 1.1, opacity: 0, duration: 0.5, ease: "power2.in" });
      }
    }
    li.setAttribute("data-done", String(!!tr && !tr.voice && tr.at === TRACK.length - 1));
    if (p.trackNote) {
      var noteText = tr ? tr.steps[tr.at].label + " · этап " + (tr.at + 1) + " из " + tr.steps.length : "этап не распознан";
      if (p.trackNote.textContent !== noteText) p.trackNote.textContent = noteText;
    }
    if (!tr) { p.track.hidden = true; return; }
    p.track.hidden = false;
    var trackKey = (tr.voice ? "v" : "t");
    if (p.track.__r2oKey !== trackKey) {
      p.track.__r2oKey = trackKey;
      p.track.replaceChildren(p.fill, p.puck);
      var icons = tr.voice ? VOICE_ICONS : TRACK_ICONS;
      tr.steps.forEach(function (step, index) {
        var node = el(doc, "span", "track-step");
        var iconNode = svgEl(doc, "svg", { viewBox: "0 0 16 16", "aria-hidden": "true" }, "track-icon");
        iconNode.appendChild(svgEl(doc, "path", { d: icons[index] || "M3 8h10" }));
        node.appendChild(iconNode);
        node.appendChild(el(doc, "span", "track-label", step.label));
        p.track.appendChild(node);
      });
      p.track.style.setProperty("--steps", String(tr.steps.length));
    }
    var steps = p.track.querySelectorAll(".track-step");
    var paint = function (cur, target) {
      for (var i = 0; i < steps.length; i++) {
        steps[i].setAttribute("data-state", i === target && cur >= target - 0.02 ? "now" : i < cur + 0.02 ? "past" : "next");
      }
    };
    var oldAt = p.track.__r2oAt;
    p.track.__r2oAt = tr.at;
    if (p.track.__tween) p.track.__tween.kill();
    if (oldAt !== undefined && oldAt !== tr.at && Motion.on()) {
      /* Маркер переезжает к новому этапу; точки загораются, когда он их проходит. */
      var pos = { at: oldAt };
      p.track.__tween = Motion.g.to(pos, { at: tr.at, duration: 0.32, ease: "power3.inOut", onUpdate: function () {
        p.track.style.setProperty("--at", String(pos.at));
        paint(pos.at, tr.at);
      } });
      Motion.g.fromTo(p.puck, { scale: 1 }, { scale: 1.7, duration: 0.22, delay: 0.75, yoyo: true, repeat: 1, ease: "power2.out" });
    } else {
      p.track.style.setProperty("--at", String(tr.at));
      paint(tr.at, tr.at);
    }
    if (oldStage !== undefined && oldStage !== stageKey && Motion.on()) {
      var currentIcon = p.track.querySelector('.track-step[data-state="now"] .track-icon');
      if (currentIcon) {
        Motion.g.fromTo(currentIcon, { scale: .6, autoAlpha: .2 }, {
          scale: 1, autoAlpha: 1, duration: .38, ease: "back.out(2.2)",
          transformOrigin: "50% 50%", clearProps: "all"
        });
      }
    }
  };

  App.prototype.updateClock = function (li) {
    var doc = this.doc, p = li.__parts;
    var text = li.__since ? clock(this.serverNow() - li.__since) : "—";
    if (!p.clock.firstChild) add(p.clock, el(doc, "strong"), el(doc, "span"));
    p.clock.firstChild.textContent = text;
    p.clock.firstChild.title = li.__since ? "С " + localTime(li.__since) : "";
    p.clock.lastChild.textContent = li.__counters || "идёт";
  };

  App.prototype.tick = function () {
    var rows = this.$("searches").children;
    for (var i = 0; i < rows.length; i++) {
      if (rows[i].__parts) this.updateClock(rows[i]);
      else if (rows[i].__r2oKey === "queue") this.updateQueue(rows[i], this.m ? this.m.queued : []);
    }
    var staleBefore = bodyAttribute(this.doc, "data-stale");
    this.renderNotice();
    var staleAfter = bodyAttribute(this.doc, "data-stale");
    if (this.m && staleBefore !== staleAfter) this.renderTelegram(this.m);
  };

  /* ─── Каталог: семейства и коробки ─── */

  App.prototype.matches = function (text) {
    return !this.filter || normName(text).indexOf(this.filter) >= 0;
  };

  App.prototype.renderCatalog = function (force) {
    var m = this.m;
    if (!m) return;
    var key = JSON.stringify([this.filter, m.linked, m.k.catalog_at, m.groups, m.boxes, this.status.snapshot.catalog_available]);
    if (!force && key === this.catalogKey) return;
    this.catalogKey = key;
    var self = this;
    this.renderFamilies(m);
    this.renderBoxes(m);
    var families = m.groups.filter(function (g) { return self.familyMatches(g); }).length;
    var bindings = 0;
    m.boxes.forEach(function (b) { list(b.bindings).forEach(function (bd) { if (self.matches(bd.target)) bindings++; }); });
    var c = this.$("filter-count");
    c.textContent = this.filter
      ? "Найдено: " + count(families, "семейство", "семейства", "семейств") + " · " + count(bindings, "цель", "цели", "целей")
      : "";
    var clear = this.$("filter-clear");
    if (clear) clear.hidden = !this.filter;
  };

  App.prototype.familyMatches = function (g) {
    var self = this;
    return this.matches(g.suffix) || list(g.evidence).some(function (e) { return self.matches(e); });
  };

  App.prototype.renderFamilies = function (m) {
    var doc = this.doc, self = this;
    var body = this.$("families-body");
    section(body, JSON.stringify([this.filter, m.linked, m.groups]), function () {
      var groups = m.groups.filter(function (g) { return self.familyMatches(g); });
      if (!m.groups.length) {
        var e = el(doc, "p", "empty");
        add(e, el(doc, "b", "", "Семейств пока нет. "),
          "Они появляются, когда один и тот же обход подтверждается на нескольких доменах одного суффикса.");
        return [e];
      }
      if (!groups.length) return [el(doc, "p", "empty", "Ни одно семейство не подходит под запрос.")];
      var cards = [];
      groups.forEach(function (g) {
        var active = !!(m.linked && g.active);
        var fid = "fam:" + JSON.stringify([g.suffix, g.family, g.transport, g.shape, g.probe_path || "/", g.ech_origin || ""]);
        var card = el(doc, "details", "family-card");
        card.setAttribute("data-key", fid);
        card.setAttribute("data-flip-id", fid);
        card.setAttribute("data-active", String(active));
        /* Совпадение только по доказательству раскрывает семейство: иначе
           найденный домен остался бы скрытым внутри строки. */
        if (self.filter && !self.matches(g.suffix)) card.open = true;

        var summary = el(doc, "summary", "family-summary");
        var glyph = el(doc, "span", "family-glyph", "*.");
        glyph.setAttribute("aria-hidden", "true");
        var main = el(doc, "div", "family-main");
        var name = el(doc, "h3", "family-name");
        add(name, el(doc, "span", "", "*."), str(g.suffix));
        var ctx = el(doc, "div", "family-ctx");
        add(ctx, tag(doc, shapeLabel(g.shape, g.transport)), tag(doc, familyLabel(g.family)));
        if (g.ech_origin) ctx.appendChild(tag(doc, "ECH: " + g.ech_origin));
        if (g.probe_path && g.probe_path !== "/") ctx.appendChild(tag(doc, "путь " + g.probe_path));
        add(main, name, ctx);

        var ev = list(g.evidence);
        var dead = [], seen = {};
        list(g.exceptions).forEach(function (x) {
          var nm = str(x && typeof x === "object" ? x.name : x);
          if (!nm || seen[nm]) { if (nm) seen[nm].n++; return; }
          seen[nm] = { name: nm, reason: str(x && x.reason) || "общий план не подошёл", n: 1 };
          dead.push(seen[nm]);
        });
        var stat = el(doc, "span", "family-stat");
        add(stat, el(doc, "b", "", String(num(g.evidence_count) || ev.length)),
          " " + plural(num(g.evidence_count) || ev.length, "домен", "домена", "доменов"));
        if (dead.length) stat.appendChild(doc.createTextNode(" · без плана " + dead.length));
        var stamp = el(doc, "span", "family-status", active ? "Применяется" : "Не подтверждено");
        stamp.setAttribute("data-active", String(active));
        if (!active) stamp.title = "Решение сохранено, но применение к семейству сейчас не подтверждено";
        var chevron = svgEl(doc, "svg", { viewBox: "0 0 24 24", "aria-hidden": "true" }, "family-chevron");
        chevron.appendChild(svgEl(doc, "path", { d: "m7 10 5 5 5-5" }));
        add(summary, glyph, main, stat, stamp, chevron);

        var wrap = el(doc, "div", "family-body");
        var inner = el(doc, "div", "family-body-inner");
        var grid = el(doc, "div", "family-grid");
        var evidence = el(doc, "div", "family-block");
        evidence.appendChild(el(doc, "h4", "", "Подтверждено на " +
          count(num(g.evidence_count) || ev.length, "домене", "доменах", "доменах")));
        var tree = el(doc, "ul", "family-tree");
        ev.forEach(function (d) { tree.appendChild(el(doc, "li", "", d)); });
        dead.forEach(function (x) {
          var li = el(doc, "li", "ex");
          add(li, x.name, el(doc, "small", "", " — " + x.reason.toLowerCase() + (x.n > 1 ? " (планов: " + x.n + ")" : "")));
          tree.appendChild(li);
        });
        if (!ev.length && !dead.length) tree.appendChild(el(doc, "li", "", "Домены-доказательства не записаны."));
        evidence.appendChild(tree);

        var side = el(doc, "div", "family-block");
        side.appendChild(el(doc, "h4", "", "План и коробки"));
        var plan = el(doc, "div", "family-plan");
        if (g.plan_id) {
          plan.appendChild(el(doc, "code", "", str(g.plan_id)));
          var owners = [];
          m.boxes.forEach(function (b, bi) {
            if (list(b.plans).some(function (p) { return p.id === g.plan_id; })) owners.push({ id: str(b.id), n: bi + 1 });
          });
          if (owners.length) {
            var links = el(doc, "span", "family-boxes", owners.length > 1 ? "в коробках " : "в коробке ");
            owners.forEach(function (o, oi) {
              if (oi) links.appendChild(doc.createTextNode(" · "));
              var b = el(doc, "button", "family-box", String(o.n));
              b.type = "button";
              b.setAttribute("aria-label", "Показать коробку " + o.n);
              b.addEventListener("click", function () { self.showBox(o.id); });
              links.appendChild(b);
            });
            plan.appendChild(links);
          }
        } else {
          plan.appendChild(el(doc, "span", "box-dates", "План не записан."));
        }
        side.appendChild(plan);
        add(grid, evidence, side);
        inner.appendChild(grid);
        wrap.appendChild(inner);
        card.append(summary, wrap);
        card.addEventListener("toggle", function () {
          if (card.__restoring) { card.__restoring = false; return; }
          if (!card.open || !Motion.on()) return;
          var bits = card.querySelectorAll(".family-tree li, .family-plan > *");
          if (bits.length) Motion.g.fromTo(bits, { y: 7, autoAlpha: 0 }, { y: 0, autoAlpha: 1, duration: 0.32, stagger: 0.025, ease: "power3.out", clearProps: "all" });
        });
        cards.push(card);
      });
      return cards;
    });
    var meta = this.$("families-meta");
    if (meta) {
      var key = JSON.stringify([m.groups.length, m.groups.filter(function (g) { return g.active; }).length, this.filter]);
      if (meta.__r2oKey !== key) {
        meta.__r2oKey = key;
        meta.replaceChildren();
        var total = el(this.doc, "span", "meta-chip");
        add(total, el(this.doc, "b", "", String(m.groups.length)), " " + plural(m.groups.length, "семейство", "семейства", "семейств"));
        meta.appendChild(total);
        var active = m.groups.filter(function (g) { return g.active; }).length;
        var activeChip = el(this.doc, "span", "meta-chip", active + " " + plural(active, "применяется", "применяются", "применяются"));
        if (active) activeChip.setAttribute("data-tone", "live");
        meta.appendChild(activeChip);
      }
    }
  };

  /* Переход от семейства к коробке: переключаем раздел, находим запись,
     раскрываем её и подсвечиваем. */
  App.prototype.showBox = function (id) {
    var self = this, doc = this.doc;
    if (this.screen !== "boxes") {
      this.showScreen("boxes", { instant: true });
    }
    var find = function () {
      var cards = doc.querySelectorAll("#boxes-body .box-card");
      for (var i = 0; i < cards.length; i++) if (cards[i].getAttribute("data-key") === "box:" + id) return cards[i];
      return null;
    };
    var open = function () {
      var card = find();
      if (!card) {
        if (!self.filter) return;
        self.filter = "";
        var input = self.$("filter");
        if (input) input.value = "";
        var clear = self.$("filter-clear");
        if (clear) clear.hidden = true;
        self.renderCatalog(true);
        self.win.setTimeout(open, 30);
        return;
      }
      card.open = true;
      card.classList.add("is-target");
      var summary = card.querySelector(".box-summary");
      if (summary && summary.focus) summary.focus({ preventScroll: true });
      var top = card.getBoundingClientRect().top + self.win.pageYOffset - 86;
      self.win.scrollTo({ top: top, behavior: Motion.on() ? "smooth" : "auto" });
      if (Motion.on()) {
        Motion.g.fromTo(card, { boxShadow: "0 0 0 3px rgba(185,138,82,.32)" },
          { boxShadow: "0 0 0 0 rgba(185,138,82,0)", duration: 1.2, ease: "power2.out", clearProps: "boxShadow" });
      }
      self.win.setTimeout(function () { card.classList.remove("is-target"); }, 1600);
    };
    if (find()) open();
    else {
      /* Фильтр мог скрыть нужную коробку: сначала показываем весь каталог. */
      if (this.filter) {
        this.filter = "";
        var input = this.$("filter");
        if (input) input.value = "";
        this.renderCatalog(true);
      }
      this.win.setTimeout(open, 40);
    }
  };

  App.prototype.renderBoxes = function (m) {
    var doc = this.doc, self = this;
    var body = this.$("boxes-body");
    var available = this.status.snapshot.catalog_available !== false || m.boxes.length;
    section(body, JSON.stringify([this.filter, m.linked, available, m.boxes, m.groups]), function () {
      if (!available) {
        var na = el(doc, "p", "empty");
        add(na, el(doc, "b", "", "Каталог не открыт. "), "Сохранённые коробки и решения сейчас недоступны — это не означает, что их нет.");
        return [na];
      }
      if (!m.boxes.length) {
        var e = el(doc, "p", "empty");
        add(e, el(doc, "b", "", "Каталог пуст. "),
          "Коробка появится, когда R2O подтвердит блокировку, измерит её поведение и найдёт обход. Начальных списков нет — всё узнаётся по живому трафику.");
        return [e];
      }
      var out = [];
      m.boxes.forEach(function (b, bi) {
        var binds = list(b.bindings);
        var visible = [], covered = [];
        binds.forEach(function (bd) {
          if (!self.matches(bd.target)) return;
          var g = m.linked ? coveredBy(bd, m.groups) : null;
          (g ? covered : visible).push({ bd: bd, g: g });
        });
        if (self.filter && !visible.length && !covered.length) return;
        out.push(self.boxNode(b, bi, visible, covered, binds.length));
      });
      if (!out.length) return [el(doc, "p", "empty", "Ни одна цель в коробках не подходит под запрос.")];
      return out;
    });
    var meta = this.$("boxes-meta");
    if (meta) {
      var key = JSON.stringify([m.boxes.length, m.boxes.reduce(function (sum, b) { return sum + list(b.bindings).length; }, 0), this.filter]);
      if (meta.__r2oKey !== key) {
        meta.__r2oKey = key;
        meta.replaceChildren();
        var boxes = el(this.doc, "span", "meta-chip");
        add(boxes, el(this.doc, "b", "", String(m.boxes.length)), " " + plural(m.boxes.length, "коробка", "коробки", "коробок"));
        meta.appendChild(boxes);
        var targets = m.boxes.reduce(function (sum, b) { return sum + list(b.bindings).length; }, 0);
        meta.appendChild(el(this.doc, "span", "meta-chip", targets + " " + plural(targets, "цель", "цели", "целей")));
      }
    }
  };

  function svgEl(doc, tag, attrs, cls) {
    var n = doc.createElementNS(SVG, tag);
    for (var k in attrs) n.setAttribute(k, attrs[k]);
    if (cls) n.setAttribute("class", cls);
    return n;
  }

  function boxFacts(binds) {
    var protos = {}, v6 = false, recheck = 0, off = 0;
    binds.forEach(function (bd) {
      protos[shapeLabel(bd.shape, bd.transport)] = true;
      if (bd.family === 6) v6 = true;
      if (bd.recheck) recheck++;
      if (bd.enabled === false) off++;
    });
    return { protos: Object.keys(protos), v6: v6, recheck: recheck, off: off };
  }

  App.prototype.boxNode = function (b, bi, visible, covered, total) {
    var doc = this.doc, self = this;
    var card = el(doc, "details", "box-card");
    card.setAttribute("data-key", "box:" + str(b.id));
    card.setAttribute("data-flip-id", "box:" + str(b.id));
    if (this.filter) card.open = true;
    var sigs = list(b.signals);
    var first = sigs.length ? (str(sigs[0].human) || str(sigs[0].kind)) : "приметы не записаны";
    var facts = boxFacts(list(b.bindings));
    var nPlans = list(b.plans).length;

    var summary = el(doc, "summary", "box-summary");
    var number = el(doc, "span", "box-number", ("0" + (bi + 1)).slice(-2));
    var main = el(doc, "div", "box-main");
    var name = el(doc, "h3", "box-name", "Коробка " + (bi + 1));
    name.appendChild(el(doc, "code", "", str(b.id)));
    add(main, name, el(doc, "p", "box-signal", first + (sigs.length > 1 ? " · ещё " + (sigs.length - 1) : "")));

    var meta = el(doc, "div", "box-meta");
    facts.protos.forEach(function (p) { meta.appendChild(tag(doc, p)); });
    if (facts.v6) meta.appendChild(tag(doc, "IPv6"));
    if (facts.recheck) meta.appendChild(tag(doc, "перепроверяется: " + facts.recheck, "live"));
    if (facts.off) meta.appendChild(tag(doc, "выключено: " + facts.off, "mute"));
    var updated = parseTime(b.updated);
    if (updated) meta.appendChild(el(doc, "span", "box-when", "обновлена " + ago(this.serverNow() - updated)));

    var countBox = el(doc, "div", "box-count");
    add(countBox, el(doc, "strong", "", String(total)), el(doc, "span", "", plural(total, "цель", "цели", "целей") + " · " + count(nPlans, "план", "плана", "планов")));
    var chevron = svgEl(doc, "svg", { viewBox: "0 0 24 24", "aria-hidden": "true" }, "box-chevron");
    chevron.appendChild(svgEl(doc, "path", { d: "m7 10 5 5 5-5" }));
    add(summary, number, main, meta, countBox, chevron);

    var wrap = el(doc, "div", "box-body");
    var inner = el(doc, "div", "box-body-inner");
    var columns = el(doc, "div", "box-columns");
    var aside = el(doc, "div", "box-aside");
    var mainCol = el(doc, "div", "box-main-col");

    var dates = [];
    var created = parseTime(b.created);
    if (created) dates.push("найдена " + localTime(created));
    if (updated && updated !== created) dates.push("обновлена " + localTime(updated));
    if (dates.length) aside.appendChild(el(doc, "p", "box-dates", dates.join(" · ")));

    var sigWrap = el(doc, "div");
    sigWrap.appendChild(el(doc, "h4", "", "Поведение"));
    if (sigs.length) {
      var sl = el(doc, "ul", "signal-list");
      sigs.forEach(function (s) {
        var li = el(doc, "li", "", str(s.human) || str(s.kind));
        if (num(s.seen)) li.appendChild(el(doc, "small", "", "×" + s.seen));
        sl.appendChild(li);
      });
      sigWrap.appendChild(sl);
    } else {
      sigWrap.appendChild(el(doc, "p", "box-dates", "Приметы не записаны"));
    }
    aside.appendChild(sigWrap);

    var plansWrap = el(doc, "div");
    plansWrap.appendChild(el(doc, "h4", "", "Планы"));
    var plans = el(doc, "div", "plans");
    list(b.plans).forEach(function (p, pi) {
      var d = el(doc, "details", "plan");
      d.setAttribute("data-key", "plan:" + str(b.id) + ":" + (p.id || pi));
      d.setAttribute("data-enabled", String(p.enabled !== false));
      var sum = el(doc, "summary");
      add(sum,
        tag(doc, str(p.proto).toUpperCase() || "—"),
        el(doc, "span", "plan-gist", str(p.human) || planGist(p.text) || str(p.id)),
        el(doc, "span", "plan-wins", count(num(p.successes) || 0, "успех", "успеха", "успехов")));
      var pre = el(doc, "pre", "", (p.id ? "# " + p.id + (p.enabled === false ? " (выключен)" : "") + "\n" : "") + str(p.text));
      pre.tabIndex = 0;
      pre.setAttribute("aria-label", "Текст плана " + (str(p.id) || String(pi + 1)));
      add(d, sum, pre);
      plans.appendChild(d);
    });
    if (!list(b.plans).length) plans.appendChild(el(doc, "p", "box-dates", "Планов нет"));
    plansWrap.appendChild(plans);
    aside.appendChild(plansWrap);

    mainCol.appendChild(el(doc, "h4", "", count(total, "цель", "цели", "целей")));
    if (visible.length) {
      var tableWrap = el(doc, "div", "table-scroll");
      var table = el(doc, "table", "bindings");
      var cg = el(doc, "colgroup");
      ["c-target", "c-proto", "c-level", "c-wins", "c-when"].forEach(function (c) { cg.appendChild(el(doc, "col", c)); });
      table.appendChild(cg);
      var thead = el(doc, "thead"), hr = el(doc, "tr");
      ["Цель", "Протокол", "Доказательство", "Успехи", "Подтверждено"].forEach(function (h) { hr.appendChild(el(doc, "th", "", h)); });
      thead.appendChild(hr);
      var tb = el(doc, "tbody");
      var now = self.serverNow();
      visible.sort(function (a, c) { return (parseTime(c.bd.confirmed) || 0) - (parseTime(a.bd.confirmed) || 0); });
      visible.forEach(function (v) {
        var bd = v.bd;
        var tr = el(doc, "tr");
        tr.setAttribute("data-enabled", String(bd.enabled !== false));
        var t = el(doc, "td", "t", targetLabel(bd.target));
        if (bd.kind === "addr") t.appendChild(el(doc, "small", "", "адрес"));
        var proto = el(doc, "td", "n c-proto", shapeLabel(bd.shape, bd.transport) + " · " + familyLabel(bd.family));
        var lv = el(doc, "td", "c-level");
        add(lv, tag(doc, str(bd.level_name) || "не измерено", (bd.level || 0) >= 3 ? "ok" : (bd.level || 0) > 0 ? "warn" : "mute"));
        if (bd.recheck) add(lv, " ", tag(doc, "перепроверяется", "live"));
        if (bd.enabled === false) add(lv, " ", tag(doc, "выключено", "mute"));
        var nw = num(bd.successes) || 0;
        var wins = el(doc, "td", "n c-wins", String(nw));
        var c = parseTime(bd.confirmed);
        var when = el(doc, "td", "n c-when", c ? ago(now - c) : "—");
        if (c) when.title = localTime(c);
        proto.setAttribute("data-tail", count(nw, "успех", "успеха", "успехов") + " · " + (c ? ago(now - c) : "время неизвестно"));
        add(tr, t, proto, lv, wins, when);
        tb.appendChild(tr);
      });
      add(table, thead, tb);
      tableWrap.appendChild(table);
      mainCol.appendChild(tableWrap);
    } else if (!covered.length) {
      mainCol.appendChild(el(doc, "p", "box-dates", "Привязанных целей нет"));
    }
    if (covered.length) {
      var det = el(doc, "details", "covered");
      det.setAttribute("data-key", "covered:" + str(b.id));
      det.appendChild(el(doc, "summary", "",
        (visible.length ? "Ещё " : "") + count(covered.length, "цель покрыта", "цели покрыты", "целей покрыты") + " семействами"));
      var ul = el(doc, "ul");
      covered.forEach(function (v) { ul.appendChild(el(doc, "li", "", targetLabel(v.bd.target) + " → *." + v.g.suffix)); });
      det.appendChild(ul);
      mainCol.appendChild(det);
    }
    add(columns, aside, mainCol);
    inner.appendChild(columns);
    wrap.appendChild(inner);
    add(card, summary, wrap);
    card.addEventListener("toggle", function () {
      if (card.__restoring) { card.__restoring = false; return; }
      if (!card.open || !Motion.on()) return;
      var bits = card.querySelectorAll(".box-aside > *, .bindings tbody tr, .covered");
      if (bits.length) Motion.g.fromTo(bits, { y: 8, autoAlpha: 0 }, { y: 0, autoAlpha: 1, duration: 0.32, stagger: 0.018, ease: "power3.out", clearProps: "all" });
    });
    return card;
  };

  /* ─── Telegram ─── */

  var TG = {
    connected: { word: "Подключён", lamp: "ok", note: "Получен подтверждённый ответ Telegram." },
    connecting: { word: "Подключается", lamp: "warn", note: "Служба запущена и проверяет доступные маршруты." },
    local: { word: "Локальный прокси", lamp: "warn", note: "Прокси запущен. Ответ Telegram появится после подтверждённого обмена." },
    unavailable: { word: "Маршрут недоступен", lamp: "bad", note: "Нет активного маршрута Telegram." },
    stopped: { word: "Остановлен", lamp: "idle", note: "Служба не запущена." },
    not_configured: { word: "Не настроен", lamp: "idle", note: "Для C11 укажите TG_MODE=local в конфигурации." }
  };

  function tunnelScene(doc) {
    var root = el(doc, "div", "tg-flow");
    var top = el(doc, "div", "tg-flow-top");
    var status = el(doc, "div", "tg-flow-status");
    var title = el(doc, "h3", "tg-flow-title");
    var lamp = el(doc, "span", "tg-flow-lamp");
    lamp.setAttribute("data-tg-state-lamp", "");
    lamp.setAttribute("aria-hidden", "true");
    var titleText = el(doc, "span", "", "Локальный прокси");
    titleText.setAttribute("data-tg-state-title", "");
    title.append(lamp, titleText);
    var note = el(doc, "p", "tg-state-note", "Служба не запущена.");
    note.setAttribute("data-tg-state-note", "");
    var actions = el(doc, "div", "tg-flow-actions");
    actions.setAttribute("data-tg-actions", "");
    status.append(title, note);
    top.append(status, actions);

    var stage = el(doc, "div", "tg-flow-stage");
    var canvas = el(doc, "canvas", "tg-flow-canvas");
    canvas.width = 960;
    canvas.height = 420;
    canvas.setAttribute("role", "img");
    canvas.setAttribute("aria-label", "Поток соединений: клиент → r2o → Telegram DC");
    stage.appendChild(canvas);
    var caption = el(doc, "p", "tg-flow-caption", "Прокси устанавливает соединение");
    caption.id = "tg-flow-caption";
    var metrics = el(doc, "div", "tg-flow-metrics");
    [
      ["Сессии сейчас", "data-tg-active-count"],
      ["Всего подключений", "data-tg-accepted-count"],
      ["Ответы Telegram", "data-tg-confirmed-count"],
      ["Задержка p50 / p95", "data-tg-latency"],
      ["WSS отказы / попытки", "data-tg-wss"],
      ["Трафик ↑ / ↓", "data-tg-traffic"]
    ].forEach(function (item) {
      var metric = el(doc, "div", "tg-flow-metric");
      metric.append(el(doc, "span", "", item[0]), el(doc, "b", "", "0"));
      metric.lastChild.setAttribute(item[1], "");
      metrics.appendChild(metric);
    });
    var diagnostics = el(doc, "details", "tg-check-details");
    var diagnosticSummary = el(doc, "summary", "", "Проверка маршрутов DC1–DC5");
    var diagnosticState = el(doc, "p", "tg-check-state", "Активная проверка ещё не запускалась.");
    diagnosticState.setAttribute("data-tg-check-state", "");
    diagnosticState.setAttribute("role", "status");
    diagnosticState.setAttribute("aria-live", "polite");
    var diagnosticTime = el(doc, "p", "tg-check-time", "");
    diagnosticTime.setAttribute("data-tg-check-time", "");
    var diagnosticCenters = el(doc, "div", "tg-check-centers");
    diagnosticCenters.setAttribute("data-tg-check-centers", "");
    diagnostics.append(diagnosticSummary, diagnosticState, diagnosticTime, diagnosticCenters);
    root.append(top, stage, caption, metrics, diagnostics);
    if (global.R2oTelegramFlow && global.R2oTelegramFlow.mountTelegramFlow) {
      root.__flow = global.R2oTelegramFlow.mountTelegramFlow(canvas);
    }
    return root;
  }

  function updateTelegramMetrics(ui, stats) {
    var scene = ui.scene;
    var rustStats = !!(stats && Number.isFinite(Number(stats.mtproto_success)));
    var active = stats ? String(Math.max(0, Number(stats.active_connections) || 0)) : "—";
    var total = stats ? String(Math.max(0, Number(stats.accepted_connections) || 0)) : "—";
    var confirmed = stats ? String(Math.max(0, Number(rustStats ? stats.mtproto_success : stats.wss_responses) || 0)) : "—";
    var activeNode = scene.querySelector("[data-tg-active-count]");
    var totalNode = scene.querySelector("[data-tg-accepted-count]");
    var confirmedNode = scene.querySelector("[data-tg-confirmed-count]");
    var latencyNode = scene.querySelector("[data-tg-latency]");
    var wssNode = scene.querySelector("[data-tg-wss]");
    var trafficNode = scene.querySelector("[data-tg-traffic]");
    var confirmedLabel = confirmedNode && confirmedNode.parentElement.querySelector("span");
    var wssLabel = wssNode && wssNode.parentElement.querySelector("span");
    var trafficLabel = trafficNode && trafficNode.parentElement.querySelector("span");
    if (confirmedLabel) confirmedLabel.textContent = rustStats ? "Успехи MTProto" : "Ответы Telegram";
    if (wssLabel) wssLabel.textContent = rustStats ? "MTProto отказы / результаты" : "WSS отказы / попытки";
    if (trafficLabel) trafficLabel.textContent = rustStats &&
      !(Number.isFinite(Number(stats.bytes_from_clients)) && Number.isFinite(Number(stats.bytes_from_upstreams)))
      ? "Трафик ↑ / ↓ (нет данных)" : "Трафик ↑ / ↓";
    if (activeNode && activeNode.textContent !== active) activeNode.textContent = active;
    if (totalNode && totalNode.textContent !== total) totalNode.textContent = total;
    if (confirmedNode && confirmedNode.textContent !== confirmed) confirmedNode.textContent = confirmed;
    var latencySamples = Number(stats && stats.client_response_latency_samples) || 0;
    var p50us = Number(stats && stats.client_response_latency_p50_us);
    var p95us = Number(stats && stats.client_response_latency_p95_us);
    var rustTtfb = stats && stats.ttfb && typeof stats.ttfb === "object"
      ? Object.values(stats.ttfb).filter(function (sample) { return Number(sample && sample.count) > 0; }) : [];
    var latency = latencySamples > 0 && Number.isFinite(p50us) && Number.isFinite(p95us)
      ? telegramMilliseconds(p50us / 1000).replace(/ мс$/, "") + " / " +
        telegramMilliseconds(p95us / 1000)
      : rustTtfb.length === 1 && Number.isFinite(Number(rustTtfb[0].p50_ms)) && Number.isFinite(Number(rustTtfb[0].p95_ms))
        ? telegramMilliseconds(rustTtfb[0].p50_ms).replace(/ мс$/, "") + " / " + telegramMilliseconds(rustTtfb[0].p95_ms)
        : "—";
    var wss = rustStats
      ? (Number(stats.mtproto_failure) || 0) + " / " + ((Number(stats.mtproto_success) || 0) + (Number(stats.mtproto_failure) || 0))
      : stats ? (Number(stats.wss_failures) || 0) + " / " + (Number(stats.wss_attempts) || 0) : "—";
    var hasTraffic = stats && Number.isFinite(Number(stats.bytes_from_clients)) && Number.isFinite(Number(stats.bytes_from_upstreams));
    var traffic = hasTraffic ? telegramBytes(stats.bytes_from_clients) + " / " + telegramBytes(stats.bytes_from_upstreams) : "—";
    if (latencyNode && latencyNode.textContent !== latency) latencyNode.textContent = latency;
    if (wssNode && wssNode.textContent !== wss) wssNode.textContent = wss;
    if (trafficNode && trafficNode.textContent !== traffic) trafficNode.textContent = traffic;
  }

  function renderTelegramDiagnostics(root, report) {
    if (!root) return;
    report = report && typeof report === "object" ? report : { state: "never" };
    var key = JSON.stringify(report);
    if (root.__r2oKey === key) return;
    root.__r2oKey = key;
    var status = root.querySelector("[data-tg-check-state]");
    var checked = root.querySelector("[data-tg-check-time]");
    var centers = root.querySelector("[data-tg-check-centers]");
    var states = {
      healthy: "Все пять DC подтвердили обмен MTProto resPQ.",
      partial: "resPQ подтверждён не для всех дата-центров.",
      unavailable: "Маршрут с подтверждённым resPQ не найден.",
      unverified: "Ответ resPQ не подтверждён ни для одного дата-центра.",
      running: "Проверяются маршруты; успех засчитывается только после resPQ.",
      never: "Активная проверка ещё не запускалась.",
      error: str(report.message) || "Не удалось запустить проверку маршрутов."
    };
    if (status) status.textContent = states[report.state] || "Результат проверки не распознан.";
    if (checked) {
      checked.textContent = Number.isFinite(Number(report.checked_at)) && Number(report.checked_at) > 0
        ? "Проверено: " + new Date(Number(report.checked_at) * 1000).toLocaleString("ru-RU") : "";
    }
    if (!centers) return;
    centers.replaceChildren();
    if (!Array.isArray(report.data_centers)) return;
    var dcStates = {
      healthy: "resPQ подтверждён", blocked: "маршруты заблокированы",
      unavailable: "нет подтверждённого маршрута", unverified: "не подтверждено"
    };
    var routeStates = {
      healthy: "resPQ подтверждён", blocked: "заблокирован",
      unavailable: "не прошёл", unverified: "не подтверждено"
    };
    var transports = {
      "direct-wss": "Прямой WSS", "cloudflare-worker": "Cloudflare Worker",
      "cloudflare-proxy": "Прокси Cloudflare", "tcp-fallback": "Резервный TCP"
    };
    var timings = [["dns_ms", "DNS"], ["tcp_ms", "TCP"], ["tls_ms", "TLS"],
      ["websocket_ms", "WebSocket"], ["mtproto_ms", "resPQ"]];
    report.data_centers.forEach(function (dc) {
      if (!dc || !Number.isInteger(Number(dc.dc)) || Number(dc.dc) < 1 || Number(dc.dc) > 5) return;
      var details = el(root.ownerDocument, "details", "tg-check-dc");
      var label = "DC" + Number(dc.dc) + " · " + (dcStates[dc.state] || "статус неизвестен");
      details.appendChild(el(root.ownerDocument, "summary", "", label));
      var list = el(root.ownerDocument, "ul", "tg-check-routes");
      (Array.isArray(dc.routes) ? dc.routes : []).forEach(function (route) {
        if (!route || typeof route !== "object") return;
        var item = el(root.ownerDocument, "li", "tg-check-route");
        var name = transports[route.transport] || str(route.transport) || "Маршрут";
        var parts = [name, routeStates[route.state] || "статус неизвестен"];
        if (route.domain) parts.push(str(route.domain));
        if (route.selected_ip) parts.push(str(route.selected_ip));
        if (route.failed_stage) parts.push("сбой: " + str(route.failed_stage));
        if (route.http_status !== null && route.http_status !== undefined && Number.isFinite(Number(route.http_status))) {
          parts.push("HTTP " + Number(route.http_status));
        }
        timings.forEach(function (timing) {
          if (route[timing[0]] !== null && route[timing[0]] !== undefined && Number.isFinite(Number(route[timing[0]]))) {
            parts.push(timing[1] + " " + telegramMilliseconds(route[timing[0]]));
          }
        });
        item.appendChild(el(root.ownerDocument, "span", "", parts.join(" · ")));
        if (route.reason) item.appendChild(el(root.ownerDocument, "small", "tg-check-reason", str(route.reason)));
        list.appendChild(item);
      });
      if (!list.children.length) list.appendChild(el(root.ownerDocument, "li", "", "Маршруты не перечислены."));
      details.appendChild(list);
      centers.appendChild(details);
    });
  }

  App.prototype.renderTelegram = function (m, force) {
    if (!m) return;
    var doc = this.doc, snap = m.snap;
    var stats = snap.telegram_stats;
    var st = this.telegramState(m);
    var info = TG[st] || TG.stopped;
    var busy = snap.control_state === "running" || !!this.pending;
    var body = this.$("telegram-body");
    var stale = doc.body.getAttribute("data-stale") === "true";
    var key = JSON.stringify([st, snap.telegram_enabled, snap.telegram_configured, stats, snap.telegram_diagnostics,
      snap.controls_enabled, busy, this.pending, stale]);
    if (!force && body.__r2oKey === key) return;
    var focused = doc.activeElement && body.contains(doc.activeElement)
      ? doc.activeElement.getAttribute("data-control") : null;
    body.__r2oKey = key;
    var ui = body.__tgUi;
    if (!ui) {
      var scene = tunnelScene(doc);
      ui = body.__tgUi = {
        scene: scene,
        lamp: scene.querySelector("[data-tg-state-lamp]"),
        word: scene.querySelector("[data-tg-state-title]"),
        note: scene.querySelector("[data-tg-state-note]"),
        actions: scene.querySelector("[data-tg-actions]"),
      };
      body.replaceChildren(scene);
      if (ui.scene.__flow) ui.scene.__flow.attach();
    }
    ui.lamp.setAttribute("data-tone", info.lamp);
    ui.lamp.setAttribute("aria-label", info.word);
    if (ui.word.textContent !== "Локальный прокси") ui.word.textContent = "Локальный прокси";
    if (ui.note && ui.note.textContent !== info.note) ui.note.textContent = info.note;
    var buttons = [];
    if (snap.controls_enabled) {
      if (snap.telegram_enabled) {
        buttons.push(this.button("telegram-disable", "Выключить туннель", "stop", null, busy));
      } else {
        buttons.push(this.button("telegram-enable", "Включить туннель", "send", "primary", busy || !snap.telegram_configured));
      }
      buttons.push(this.button("telegram-check", "Проверить DC1–DC5", null, null, busy || !snap.telegram_configured));
    }
    buttons.push(this.button("telegram-workers", "Мои Workers", null, null, busy));
    ui.actions.replaceChildren.apply(ui.actions, buttons);
    body.setAttribute("data-state", st);
    ui.scene.setAttribute("data-state", st);
    if (ui.scene.__flow) ui.scene.__flow.update(stats, stale);
    updateTelegramMetrics(ui, stats);
    renderTelegramDiagnostics(ui.scene.querySelector(".tg-check-details"), snap.telegram_diagnostics);
    if (focused) {
      var again = body.querySelector("button");
      if (again) again.focus();
    }
  };

  /* ─── Диагностика ─── */

  App.prototype.drawStages = function () {
    var body = this.$("diagnostics-body"), win = global;
    if (!Motion.on()) return;
    var run = function () {
      var paths = body.querySelectorAll(".stages svg path");
      if (paths.length) Motion.g.fromTo(paths, { drawSVG: "0%" }, { drawSVG: "100%", duration: 0.35, stagger: 0.05, ease: "power2.out", clearProps: "strokeDasharray,strokeDashoffset" });
    };
    if (body.__seen) { run(); return; }
    if (typeof win.IntersectionObserver !== "function" || body.__io) return;
    body.__io = new win.IntersectionObserver(function (entries) {
      if (!entries[entries.length - 1].isIntersecting) return;
      body.__seen = true; body.__io.disconnect(); run();
    }, { threshold: 0.2 });
    body.__io.observe(body);
  };

  App.prototype.renderDiagnostics = function (m) {
    var doc = this.doc;
    var snap = m.snap;
    var body = this.$("diagnostics-body");
    var col = this.$("colophon");
    var meas = m.k.measurements || {};
    var key = JSON.stringify([snap.stages, snap.absent, snap.config_path, snap.config_exists, snap.mode, snap.state_dir,
      snap.state_dir_note, snap.queue_num, snap.unknown_keys, snap.engine_running, snap.controller_running,
      snap.live_fresh, m.linked, m.k.catalog_at, m.k.client_unfit, meas.cores, snap.controls_enabled, snap.control_state]);
    var redrawn = section(body, key, function () {
      var wrap = el(doc, "div", "diag");

      var left = el(doc, "div");
      left.appendChild(el(doc, "h3", "", "Цепочка движка"));
      var ul = el(doc, "ul", "stages");
      list(snap.stages).forEach(function (s) {
        var li = el(doc, "li");
        li.setAttribute("data-ok", String(!!s.built));
        add(li, icon(doc, s.built ? "check" : "cross"), el(doc, "b", "", str(s.title)), el(doc, "p", "", str(s.detail)));
        ul.appendChild(li);
      });
      list(snap.absent).forEach(function (s) {
        var li = el(doc, "li");
        li.setAttribute("data-absent", "true");
        add(li, icon(doc, "dash"), el(doc, "b", "", str(s.title) + " — не измеряется"), el(doc, "p", "", str(s.detail)));
        ul.appendChild(li);
      });
      if (!list(snap.stages).length && !list(snap.absent).length) ul.appendChild(el(doc, "li", "", "Сведений о цепочке нет."));
      left.appendChild(ul);

      var right = el(doc, "div");
      right.appendChild(el(doc, "h3", "", "Запуск и настройки"));
      var dl = el(doc, "dl", "facts");
      function fact(label, value, tone, mono) {
        var dd = el(doc, "dd", mono ? "mono" : "", value);
        if (tone) dd.setAttribute("data-tone", tone);
        add(dl, el(doc, "dt", "", label), dd);
      }
      fact("Режим", (MODES[snap.mode] || str(snap.mode) || "не указан") + (snap.mode ? " (MODE=" + snap.mode + ")" : ""));
      fact("Движок", snap.engine_running ? "процесс запущен" : "процесс не найден", snap.engine_running ? null : "bad");
      fact("Контроллер", snap.controller_running ? "процесс запущен" : "процесс не найден", snap.controller_running ? null : "bad");
      fact("Управление", snap.controls_enabled
        ? "включено; команды принимаются только со страницы этой панели"
        : "отключено в конфигурации", null);
      var last = { idle: "", running: "выполняется", done: "выполнена", failed: "завершилась ошибкой", timeout: "не завершилась вовремя" }[str(snap.control_state)];
      if (last) fact("Последняя команда", last, snap.control_state === "failed" || snap.control_state === "timeout" ? "warn" : null);
      if (m.panelUptime) fact("Панель запущена", duration(m.panelUptime * 1000) + " назад");
      fact("Связь с датапатом", m.linked ? "есть" : "нет", m.linked ? null : "bad");
      fact("Снимок движка", snap.live_fresh ? "свежий" : "устарел или отсутствует", snap.live_fresh ? null : "warn");
      fact("Конфигурация", str(snap.config_path) + (snap.config_exists ? "" : " — файла нет, действуют умолчания"),
        snap.config_exists ? null : "warn", true);
      fact("Каталог состояния", str(snap.state_dir) + " — " + str(snap.state_dir_note), null, true);
      if (m.k.catalog_at) fact("Файл каталога", str(m.k.catalog_at), null, true);
      if (num(snap.queue_num) !== null) fact("Очередь NFQUEUE", String(snap.queue_num), null, true);
      if (num(m.k.client_unfit) !== null) fact("План не подошёл клиенту", String(m.k.client_unfit), m.k.client_unfit ? "warn" : null);
      var unknown = list(snap.unknown_keys);
      if (unknown.length) fact("Непонятные ключи", unknown.join(", ") + " — эта сборка их не читает", "warn", true);
      right.appendChild(dl);

      add(wrap, left, right);
      return [wrap];
    });
    if (redrawn) this.drawStages();
    col.replaceChildren();
    add(col,
      el(doc, "span", "", "R2O " + str(snap.version) + (snap.dirty ? " (изменённая сборка)" : "")),
      snap.commit ? el(doc, "span", "mono", str(snap.commit).slice(0, 12)) : null,
      parseTime(snap.built) ? el(doc, "span", "", "собран " + localTime(parseTime(snap.built))) : null,
      parseTime(snap.taken) ? el(doc, "span", "", "снимок " + localTime(parseTime(snap.taken))) : null);
    var railVersion = this.$("rail-version");
    if (railVersion) {
      var version = "R2O " + str(snap.version) + (snap.dirty ? " · изменённая сборка" : "");
      if (railVersion.textContent !== version) railVersion.textContent = version;
    }
    var meta = this.$("diagnostics-meta");
    if (meta) {
      var metaKey = JSON.stringify([snap.version, snap.mode, m.linked, snap.live_fresh, list(snap.stages).filter(function (stage) { return !stage.built; }).length]);
      if (meta.__r2oKey !== metaKey) {
        meta.__r2oKey = metaKey;
        meta.replaceChildren();
        var versionChip = el(doc, "span", "meta-chip", "версия " + str(snap.version));
        meta.appendChild(versionChip);
        var modeChip = el(doc, "span", "meta-chip", "режим " + (MODES[snap.mode] || str(snap.mode) || "—"));
        meta.appendChild(modeChip);
        var bad = list(snap.stages).filter(function (stage) { return !stage.built; }).length;
        var chainChip = el(doc, "span", "meta-chip", bad ? bad + " " + plural(bad, "звено", "звена", "звеньев") + " без подтверждения" : "цепочка собрана");
        chainChip.setAttribute("data-tone", bad ? "warn" : "ok");
        meta.appendChild(chainChip);
        var linkChip = el(doc, "span", "meta-chip", m.linked ? "датапат на связи" : "нет связи с датапатом");
        linkChip.setAttribute("data-tone", m.linked ? "live" : "bad");
        meta.appendChild(linkChip);
      }
    }
  };

  /* ─── Навигация ─── */

  App.prototype.renderNav = function (m) {
    var self = this;
    var set = function (id, text, tone) {
      var n = self.$(id);
      if (!n) return;
      var changed = n.textContent !== text;
      n.textContent = text;
      if (tone) n.setAttribute("data-tone", tone); else n.removeAttribute("data-tone");
      if (changed && text && Motion.on()) {
        Motion.g.killTweensOf(n);
        Motion.g.fromTo(n, { scale: 1.35, opacity: .5 }, { scale: 1, opacity: 1, duration: .35, ease: "back.out(2.6)", clearProps: "transform,opacity" });
      }
    };
    set("nav-now", !m.engine ? "стоп" : !m.linked ? "нет связи" : m.hunting ? String(m.hunting) : "", m.hunting ? "live" : !m.engine || !m.linked ? "warn" : null);
    set("nav-families", m.groups.length ? String(m.groups.length) : "");
    set("nav-boxes", m.boxes.length ? String(m.boxes.length) : "");
    var tg = this.telegramState(m);
    set("nav-telegram", tg === "connected" ? "вкл" : tg === "local" ? "лок." : tg === "connecting" ? "…" : "выкл",
      tg === "connected" ? "live" : tg === "unavailable" ? "bad" : null);
    var bad = list(m.snap.stages).filter(function (s) { return !s.built; }).length;
    set("nav-diagnostics", bad ? "!" + bad : "", bad ? "warn" : null);
  };

  /* Знак R2O и навигация появляются один раз при загрузке. */
  App.prototype.drawMark = function () {
    if (!Motion.on()) return;
    var d = this.doc;
    var marks = d.querySelectorAll(".brand-mark, .mast-mark");
    var links = d.querySelectorAll(".index a");
    Motion.g.timeline({ delay: 0.05, defaults: { ease: "power3.out" } })
      .from(marks, { scale: 0.78, autoAlpha: 0, duration: 0.4, stagger: 0.06, ease: "back.out(2)" })
      .from(links, { x: -7, autoAlpha: 0, duration: 0.36, stagger: 0.035 }, "-=0.3")
      .set([marks, links], { clearProps: "transform,opacity,visibility" });
  };

  var api = {
    model: model, coveredBy: coveredBy, slotsView: slotsView, trackFor: trackFor, shapeLabel: shapeLabel,
    planGist: planGist, plural: plural, duration: duration,
    telegramRouteName: telegramRouteName,
    telegramFailureStage: telegramFailureStage,
    App: App
  };
  if (typeof module === "object" && module.exports) module.exports = api;
  if (global && global.document && global.document.getElementById) {
    var boot = function () { new App(global.document, global).start(); };
    if (global.document.readyState === "loading") global.document.addEventListener("DOMContentLoaded", boot);
    else boot();
  }
})(typeof window !== "undefined" ? window : this);
