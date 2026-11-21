/* Эффекты оформления работают в одном цикле кадра. GSAP ведёт переходы экрана и капсулы. */
(function (win, doc) {
  "use strict";
  if (!win || !doc) return;
  var mast = doc.getElementById("mast");
  if (!mast) return;
  var reduced = win.matchMedia("(prefers-reduced-motion: reduce)");
  var fine = win.matchMedia("(any-hover: hover) and (any-pointer: fine)");
  var surfaceSelector = [
    ".status-panel", ".metric-card", ".workload-card", ".catalog-card", ".service-card",
    ".search", ".family-card:not([open])", ".box-card:not([open])",
    ".tg-hero", ".tg-flow-card", ".tg-route", ".tg-stat", ".tg-check-dc",
    ".release-hero", ".release-card", ".auto-card", ".diag-collector",
    ".diag-card", ".diag-stat-strip > div", ".stages li"
  ].join(", ");
  var controls = "button, input, select, textarea, [role=slider], dialog, .table-scroll, canvas";
  var interactiveText = "#update-check, #diagnostic-refresh, [data-action=telegram-check], .service-card, .brand, .mast-brand";
  var decodeQueue = new Map(), decoding = new Map(), decoded = new WeakMap();
  var alphabet = "АБВГДЕЖЗКЛМНОПРСТУФХ░▒0123456789";
  var measure = doc.createElement("canvas").getContext("2d");
  var hero = doc.getElementById("status-panel");
  var canvas = hero.querySelector(".pixel-trail"), painter, trail = [], lastPixel;
  var markTrail = [], lastMark;
  var trailLimit = 40, trailLife = 510;
  var raf = 0;
  var pointer, surface, shadowDirty = true;

  function motionAllowed() { return !reduced.matches && !doc.hidden; }

  function shown(element) {
    return element && element.isConnected && !element.closest("[hidden]") && element.getClientRects().length > 0;
  }

  function reveal(element, again) {
    if (!element || !motionAllowed() || !shown(element)) return;
    var text = element.textContent.trim();
    if (!text || text.length > 65 || (!again && decoded.get(element) === text)) return;
    decodeQueue.set(element, text);
    schedule();
  }

  function enter(screen) {
    clearPointer(true);
    if (!screen) return;
    reveal(screen.querySelector(".screen-head h2, #now-title"), true);
    if (screen.id === "telegram") reveal(screen.querySelector(".tg-title"), true);
    if (screen.id === "now") {
      screen.querySelectorAll(".service-card strong").forEach(function (label) { reveal(label, true); });
    }
  }

  function stopDecode(element) {
    var job = decoding.get(element);
    if (!job) return;
    job.ink.remove();
    element.removeAttribute("data-decoding");
    decoding.delete(element);
  }

  function startDecode(element, text, now) {
    stopDecode(element);
    if (!shown(element) || element.textContent.trim() !== text) return;
    var box = element.getBoundingClientRect();
    var ink = doc.createElement("span");
    ink.className = "decode-ink";
    ink.setAttribute("aria-hidden", "true");
    var symbols = element.closest(".brand, .mast-brand") ? "r2o0A4X8▒" : alphabet;
    var widths = new Map();
    var letters = [], walker = doc.createTreeWalker(element, NodeFilter.SHOW_TEXT);
    var range = doc.createRange();
    while (walker.nextNode()) {
      var node = walker.currentNode, style = win.getComputedStyle(node.parentElement);
      var font = [style.fontStyle, style.fontWeight, style.fontSize, style.fontFamily].join(" ");
      if (!widths.has(font)) {
        if (measure) measure.font = font;
        widths.set(font, measure ? Math.max.apply(null, Array.from(symbols, function (symbol) {
          return measure.measureText(symbol).width;
        })) : parseFloat(style.fontSize));
      }
      var offset = 0;
      for (var char of node.textContent) {
        var start = offset;
        offset += char.length;
        if (/\s/.test(char)) continue;
        range.setStart(node, start);
        range.setEnd(node, offset);
        var rect = range.getBoundingClientRect();
        if (!rect.width) continue;
        var glyph = doc.createElement("span");
        glyph.style.left = (rect.left - box.left - element.clientLeft) + "px";
        glyph.style.top = (rect.top - box.top - element.clientTop) + "px";
        glyph.style.font = [style.fontStyle, style.fontWeight, style.fontSize + "/1", style.fontFamily].join(" ");
        glyph.style.setProperty("--resolved-color", style.color);
        glyph.style.setProperty("--glyph-scale", Math.min(1, rect.width / widths.get(font)));
        glyph.dataset.glyph = symbols[letters.length % symbols.length];
        ink.append(glyph);
        letters.push({ glyph: glyph, char: char });
      }
    }
    if (!letters.length) return;
    decoded.set(element, text);
    element.append(ink);
    element.setAttribute("data-decoding", "");
    decoding.set(element, { ink: ink, letters: letters, from: now, text: text, symbols: symbols, beat: -1 });
  }

  function paintText(now) {
    decodeQueue.forEach(function (text, element) { startDecode(element, text, now); });
    decodeQueue.clear();
    decoding.forEach(function (job, element) {
      var age = now - job.from;
      if (age >= 460 || !shown(element) || element.textContent.trim() !== job.text) {
        stopDecode(element);
        return;
      }
      var beat = Math.floor(age / 42);
      if (beat === job.beat) return;
      job.beat = beat;
      var through = Math.floor(Math.max(0, age - 45) / 390 * job.letters.length);
      job.letters.forEach(function (letter, index) {
        if (letter.glyph.hasAttribute("data-resolved")) return;
        if (index < through) {
          letter.glyph.dataset.glyph = letter.char;
          letter.glyph.setAttribute("data-resolved", "");
        } else {
          letter.glyph.dataset.glyph = job.symbols[(index * 11 + beat * 7) % job.symbols.length];
        }
      });
    });
  }

  function dropSpotlight() {
    if (!surface) return;
    if (surface === hero) lastPixel = null;
    surface.removeAttribute("data-r2o-spot");
    surface = null;
  }

  function clearPointer(clearTrail) {
    pointer = null;
    lastPixel = null;
    lastMark = null;
    dropSpotlight();
    if (clearTrail) {
      markTrail.forEach(function (pixel) { pixel.node.remove(); });
      markTrail.length = 0;
    }
    if (clearTrail && trail.length) {
      trail.length = 0;
      if (painter) painter.draw(trail, performance.now());
    }
  }

  function tracePixels(from, x, y, emit) {
    var distance = from ? Math.max(Math.abs(x - from.x), Math.abs(y - from.y)) : 0;
    if (from && !distance) return from;
    var steps = Math.max(1, Math.min(5, distance));
    for (var i = 1; i <= steps; i++) {
      emit(from ? Math.round(from.x + (x - from.x) * i / steps) : x,
        from ? Math.round(from.y + (y - from.y) * i / steps) : y);
    }
    return { x: x, y: y };
  }

  function traceMark(sample, now) {
    var mark = sample.target.closest(".brand-mark, .mast-mark");
    if (!mark) { lastMark = null; return; }
    var rect = mark.getBoundingClientRect();
    var scale = Math.min(rect.width, rect.height) / 40;
    if (!scale) return;
    var x = 20 + (sample.x - rect.left - rect.width / 2) / scale;
    var y = 20 + (sample.y - rect.top - rect.height / 2) / scale;
    if (x < 0 || x >= 40 || y < 5 || y >= 35) { lastMark = null; return; }
    var group = mark.querySelector(".brand-trail");
    var previous = lastMark && lastMark.mark === mark ? lastMark.cell : null;
    var cell = tracePixels(previous, Math.floor(x / 2.5), Math.floor(y / 2.5), function (column, row) {
      var node = doc.createElementNS("http://www.w3.org/2000/svg", "rect");
      node.setAttribute("x", column * 2.5);
      node.setAttribute("y", row * 2.5);
      node.setAttribute("width", "2.15");
      node.setAttribute("height", "2.15");
      if (markTrail.length >= trailLimit) markTrail.shift().node.remove();
      group.append(node);
      markTrail.push({ node: node, at: now });
    });
    lastMark = { mark: mark, cell: cell };
  }

  function paintPointer(now) {
    if (!pointer) return;
    var sample = pointer;
    pointer = null;
    traceMark(sample, now);
    var next = sample.target.closest(surfaceSelector);
    if (next !== surface || !shown(next)) dropSpotlight();
    if (!next || !shown(next)) return;
    var rect = next.getBoundingClientRect();
    if (sample.x < rect.left || sample.x > rect.right || sample.y < rect.top || sample.y > rect.bottom) {
      dropSpotlight();
      return;
    }
    var u = (sample.x - rect.left) / rect.width, v = (sample.y - rect.top) / rect.height;
    next.style.setProperty("--spot-x", (u * 100).toFixed(1) + "%");
    next.style.setProperty("--spot-y", (v * 100).toFixed(1) + "%");
    next.style.setProperty("--tilt", (0.5 - v) + " " + (u - 0.5) + " 0 " +
      (Math.hypot(u - 0.5, v - 0.5) * 4).toFixed(2) + "deg");
    next.classList.add("r2o-motion-surface");
    next.setAttribute("data-r2o-spot", sample.target.closest(controls) || next.matches(".diag-card, .diag-collector, .tg-flow-card, .stages li") ? "light" : "tilt");
    surface = next;
    if (next !== hero || sample.target.closest(controls)) { lastPixel = null; return; }
    if (!painter) painter = makePainter();
    if (!painter) return;
    var column = Math.floor(u * rect.width / 12), row = Math.floor(v * rect.height / 12);
    lastPixel = tracePixels(lastPixel, column, row, function (x, y) {
      if (trail.length >= trailLimit) trail.shift();
      trail.push({ x: x * 12 + 6, y: y * 12 + 6, at: now, bronze: (x + y) % 5 === 0 });
    });
  }

  function sizeTrail() {
    var width = canvas.clientWidth, height = canvas.clientHeight;
    if (!width || !height) return null;
    var ratio = Math.min(win.devicePixelRatio || 1, 1.5, 1400 / width);
    var w = Math.ceil(width * ratio), h = Math.ceil(height * ratio);
    if (canvas.width !== w) canvas.width = w;
    if (canvas.height !== h) canvas.height = h;
    return { width: width, height: height, ratio: ratio };
  }

  function makePainter(force2d) {
    var colors = win.getComputedStyle(doc.documentElement);
    var teal = colors.getPropertyValue("--acc").trim(), bronze = colors.getPropertyValue("--amber").trim();
    var gl;
    if (!force2d) {
      try { gl = canvas.getContext("webgl2", { antialias: false, powerPreference: "low-power", failIfMajorPerformanceCaveat: true }); }
      catch (error) { gl = null; }
    }
    if (gl) {
      var draw = pointShader(gl, teal, bronze);
      if (draw) {
        canvas.dataset.renderer = "webgl2";
        canvas.addEventListener("webglcontextlost", fallbackPainter, { once: true });
        return { draw: draw };
      }
      return fallbackPainter();
    }
    var context = canvas.getContext("2d");
    if (!context) return { draw: function () {} };
    canvas.dataset.renderer = "canvas2d";
    return { draw: function (pixels, now) {
      var size = sizeTrail();
      if (!size) return;
      context.setTransform(size.ratio, 0, 0, size.ratio, 0, 0);
      context.clearRect(0, 0, size.width, size.height);
      pixels.forEach(function (pixel) {
        var alpha = Math.max(0, 1 - (now - pixel.at) / trailLife);
        context.fillStyle = pixel.bronze ? bronze : teal;
        context.globalAlpha = alpha * .07;
        context.fillRect(pixel.x - 6, pixel.y - 6, 12, 12);
        context.globalAlpha = alpha * .28;
        context.fillRect(pixel.x - 3, pixel.y - 3, 6, 6);
      });
    } };
  }

  function fallbackPainter() {
    var replacement = canvas.cloneNode(false);
    canvas.replaceWith(replacement);
    canvas = replacement;
    painter = makePainter(true);
    return painter;
  }

  function pointShader(gl, teal, bronze) {
    var compile = function (type, source) {
      var shader = gl.createShader(type);
      gl.shaderSource(shader, source);
      gl.compileShader(shader);
      return shader;
    };
    var program = gl.createProgram();
    var vertex = compile(gl.VERTEX_SHADER, `#version 300 es
      in vec4 pixel;
      uniform float side;
      out vec2 tone;
      void main() {
        gl_Position = vec4(pixel.xy, 0.0, 1.0);
        gl_PointSize = side;
        tone = pixel.zw;
      }`);
    var fragment = compile(gl.FRAGMENT_SHADER, `#version 300 es
      precision mediump float;
      uniform vec3 teal, bronze;
      in vec2 tone;
      out vec4 light;
      void main() {
        vec2 p = abs(gl_PointCoord - 0.5);
        float fade = smoothstep(0.21, 0.48, max(p.x, p.y));
        float alpha = tone.x * mix(0.28, 0.0, fade);
        light = vec4(mix(teal, bronze, tone.y), alpha);
      }`);
    gl.attachShader(program, vertex);
    gl.attachShader(program, fragment);
    gl.linkProgram(program);
    gl.deleteShader(vertex);
    gl.deleteShader(fragment);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) { gl.deleteProgram(program); return null; }
    gl.useProgram(program);
    var buffer = gl.createBuffer(), location = gl.getAttribLocation(program, "pixel");
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.enableVertexAttribArray(location);
    gl.vertexAttribPointer(location, 4, gl.FLOAT, false, 0, 0);
    gl.enable(gl.BLEND);
    gl.blendFuncSeparate(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA, gl.ONE, gl.ONE_MINUS_SRC_ALPHA);
    var array = new Float32Array(trailLimit * 4), side = gl.getUniformLocation(program, "side");
    function rgb(hex) { return [1, 3, 5].map(function (i) { return parseInt(hex.slice(i, i + 2), 16) / 255; }); }
    gl.uniform3fv(gl.getUniformLocation(program, "teal"), rgb(teal));
    gl.uniform3fv(gl.getUniformLocation(program, "bronze"), rgb(bronze));
    return function (pixels, now) {
      var size = sizeTrail();
      if (!size || gl.isContextLost()) return;
      gl.viewport(0, 0, canvas.width, canvas.height);
      gl.clear(gl.COLOR_BUFFER_BIT);
      if (!pixels.length) return;
      gl.uniform1f(side, 13 * size.ratio);
      pixels.forEach(function (pixel, i) {
        array.set([2 * pixel.x / size.width - 1, 1 - 2 * pixel.y / size.height,
          Math.max(0, 1 - (now - pixel.at) / trailLife), Number(pixel.bronze)], i * 4);
      });
      gl.bufferData(gl.ARRAY_BUFFER, array, gl.DYNAMIC_DRAW);
      gl.drawArrays(gl.POINTS, 0, pixels.length);
    };
  }

  function update(now) {
    raf = 0;
    if (shadowDirty) {
      mast.classList.toggle("is-scrolled", (win.scrollY || win.pageYOffset || 0) > 12);
      shadowDirty = false;
    }
    if (!motionAllowed()) return;
    paintPointer(now);
    paintText(now);
    while (markTrail.length && now - markTrail[0].at >= trailLife) markTrail.shift().node.remove();
    markTrail.forEach(function (pixel) {
      var age = (now - pixel.at) / trailLife;
      pixel.node.style.setProperty("--age", Math.round(age * 100) + "%");
      pixel.node.style.opacity = .73 * (1 - age);
    });
    if (trail.length) {
      while (trail.length && now - trail[0].at >= trailLife) trail.shift();
      painter.draw(trail, now);
    }
    if (decoding.size || trail.length || markTrail.length) schedule();
  }
  function schedule() {
    if (!raf) raf = win.requestAnimationFrame(update);
  }
  function scroll() { shadowDirty = true; clearPointer(true); schedule(); }
  function reset() {
    clearPointer(true);
    decodeQueue.clear();
    decoding.forEach(function (_, element) { stopDecode(element); });
    if (raf) win.cancelAnimationFrame(raf);
    raf = 0;
  }
  win.addEventListener("scroll", scroll, { passive: true });
  win.addEventListener("resize", function () { reset(); scroll(); }, { passive: true });
  doc.addEventListener("visibilitychange", reset);
  win.addEventListener("pagehide", reset);
  reduced.addEventListener("change", reset);
  fine.addEventListener("change", reset);
  doc.addEventListener("pointermove", function (event) {
    if (!fine.matches || event.pointerType !== "mouse" || !motionAllowed()) return;
    pointer = { x: event.clientX, y: event.clientY, target: event.target };
    schedule();
  }, { passive: true });
  doc.documentElement.addEventListener("pointerleave", function () { clearPointer(false); });
  doc.addEventListener("pointerdown", function () { clearPointer(false); }, { passive: true });
  doc.addEventListener("pointerover", function (event) {
    if (!fine.matches || event.pointerType !== "mouse") return;
    var text = event.target.closest(interactiveText);
    if (text && !text.contains(event.relatedTarget)) reveal(text.querySelector("strong") || text.querySelector("span") || text, true);
  }, { passive: true });
  doc.addEventListener("focusin", function (event) {
    if (event.target.matches(interactiveText)) reveal(event.target.querySelector("strong") || event.target.querySelector("span") || event.target, true);
  });
  win.R2oPanelMotion = { enter: enter, reveal: reveal };
  schedule();
})(window, document);
