/* Always-moving purple liquid. Canvas2D field: считается в малом разрешении, растягивается браузером.
   Время копится только пока слой виден — после паузы лава продолжает с того же места, без скачка. */
(function (win, doc) {
  'use strict';
  var hero = doc.querySelector('#now .hero');
  if (!hero) return;
  var layer = hero.querySelector('.r2o-aurora');
  if (!layer) {
    layer = doc.createElement('div');
    layer.className = 'r2o-aurora';
    layer.setAttribute('aria-hidden', 'true');
    hero.insertBefore(layer, hero.firstChild);
    ['r2o-light-grain', 'r2o-cursor-shine'].forEach(function (cls) {
      var span = doc.createElement('span');
      span.className = cls; span.setAttribute('aria-hidden', 'true');
      hero.insertBefore(span, layer.nextSibling);
    });
  }
  var canvas = layer.querySelector('canvas');
  if (!canvas) { canvas = doc.createElement('canvas'); canvas.className = 'r2o-aurora-canvas'; layer.appendChild(canvas); }
  var ctx = canvas.getContext('2d', { alpha: true, willReadFrequently: false });
  if (!ctx) return;

  var reduce = win.matchMedia && win.matchMedia('(prefers-reduced-motion: reduce)');
  var reduceMotion = !!(reduce && reduce.matches);
  var onscreen = true, visible = !doc.hidden;
  var frameId = 0, lastNow = 0, lastDraw = 0, clock = 0;
  var FRAME_MS = 33;                       // ambient-слою достаточно ~30 fps
  var W = 0, H = 0, img = null;
  var posX = null, posY = null, xWave = null, xRipple = null, xWobble = null;
  var BLOBS = 6, bl = new Float32Array(BLOBS * 5);   // x, y, 1/rx, 1/ry, weight
  var RX = [.37, .35, .35, .27, .29, .38], RY = [.39, .34, .38, .33, .30, .31], WT = [1.16, 1.24, 1.14, .85, .89, .52];
  for (var k = 0; k < BLOBS; k++) { bl[k * 5 + 2] = 1 / RX[k]; bl[k * 5 + 3] = 1 / RY[k]; bl[k * 5 + 4] = WT[k]; }

  function clamp(v, a, b) { return v < a ? a : (v > b ? b : v); }
  function smoothstep(a, b, x) { x = clamp((x - a) / (b - a), 0, 1); return x * x * (3 - 2 * x); }

  function resize() {
    var r = layer.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) return false;
    var tw = clamp(Math.round(r.width * .24), 160, 360);
    var th = clamp(Math.round(r.height * .26), 90, 190);
    if (tw !== W || th !== H) {
      W = canvas.width = tw; H = canvas.height = th;
      img = ctx.createImageData(W, H);
      posX = new Float32Array(W); posY = new Float32Array(H);
      xWave = new Float32Array(W); xRipple = new Float32Array(W); xWobble = new Float32Array(W);
      for (var x = 0; x < W; x++) posX[x] = x / (W - 1);
      for (var y = 0; y < H; y++) posY[y] = y / (H - 1);
    }
    return true;
  }

  function draw(t) {
    if (!img) return;
    var p = img.data;
    bl[0] = .12 + .13 * Math.sin(.56 * t + .4);  bl[1] = .12 + .07 * Math.sin(.44 * t + 1);
    bl[5] = .48 + .14 * Math.cos(.43 * t + 1.2); bl[6] = .12 + .065 * Math.cos(.69 * t);
    bl[10] = .81 + .12 * Math.sin(.47 * t + 2.3); bl[11] = .15 + .1 * Math.cos(.51 * t + 1.2);
    bl[15] = .32 + .18 * Math.sin(.38 * t + 2.3); bl[16] = .43 + .13 * Math.cos(.62 * t + .7);
    bl[20] = .67 + .18 * Math.cos(.42 * t - .8);  bl[21] = .41 + .12 * Math.sin(.48 * t + 2);
    bl[25] = .54 + .25 * Math.sin(.36 * t + 1.7); bl[26] = .27 + .17 * Math.cos(.38 * t + 1.1);
    var x, y, i, u, v;
    for (x = 0; x < W; x++) {
      u = posX[x];
      xWave[x] = .30 + .12 * Math.sin(u * 7.4 - .57 * t) + .065 * Math.sin(u * 15.1 + .36 * t);
      xRipple[x] = .40 + .1 * Math.sin(u * 4.8 + .30 * t) + .05 * Math.cos(u * 9.0 - .41 * t);
      xWobble[x] = .025 * Math.sin(u * 16 - 1.1 * t);
    }
    var ptr = 0;
    for (y = 0; y < H; y++) {
      v = posY[y];
      var bottomFade = 1 - smoothstep(.44, 1.0, v);
      for (x = 0; x < W; x++) {
        u = posX[x];
        var wobble = xWobble[x] * (.2 + v), field = 0;
        for (i = 0; i < BLOBS; i++) {
          var o = i * 5, dx = (u - bl[o] + wobble) * bl[o + 2], dy = (v - bl[o + 1]) * bl[o + 3];
          var d = dx * dx + dy * dy;
          field += bl[o + 4] / (1.0 + d * d * 1.7);
        }
        var waveDist = (v - xWave[x]) / .25, arcDist = (v - xRipple[x]) / .31;
        field += .52 / (1 + waveDist * waveDist * waveDist * waveDist);
        field += .35 / (1 + arcDist * arcDist * arcDist * arcDist);
        var plume = smoothstep(1.75, 3.85, field);
        var edge = smoothstep(2.4, 2.95, field) * (1 - smoothstep(3.1, 3.75, field));
        var core = smoothstep(3.25, 4.8, field);
        var alpha = (.035 + .78 * plume + .09 * edge) * (.13 + .87 * bottomFade);
        var lustre = .5 + .5 * Math.sin(u * 5.7 - .35 * t + v * 3.1);
        p[ptr++] = 58 + 82 * plume + 57 * core + 9 * lustre;      // Uint8ClampedArray округляет и ограничивает сама
        p[ptr++] = 13 + 43 * plume + 56 * core + 13 * edge;
        p[ptr++] = 121 + 88 * plume + 30 * core + 10 * lustre;
        p[ptr++] = 255 * clamp(alpha, 0, .87);
      }
    }
    ctx.putImageData(img, 0, 0);
    layer.dataset.r2oLavaFrame = String(Math.round(t * 10));
  }

  function tick(now) {
    frameId = 0;
    if (!onscreen || !visible || reduceMotion) return;
    clock += lastNow ? Math.min(100, now - lastNow) * .001 : 0;
    lastNow = now;
    if (now - lastDraw >= FRAME_MS) { lastDraw = now; draw(clock); }
    frameId = win.requestAnimationFrame(tick);
  }
  function update() {
    if (frameId) { win.cancelAnimationFrame(frameId); frameId = 0; }
    lastNow = 0;
    if (onscreen && visible && !reduceMotion) frameId = win.requestAnimationFrame(tick);
  }
  function relayout() {
    if (resize()) draw(clock);          // canvas.width очищает холст — перерисовываем сразу
    if (!frameId) update();
  }

  // Cursor shine: необязательный слой, лава от указателя не зависит.
  var hoverRAF = 0;
  hero.addEventListener('pointermove', function (ev) {
    if (ev.pointerType === 'touch' || reduceMotion || hoverRAF) return;
    var rect = hero.getBoundingClientRect();
    var mx = 100 * (ev.clientX - rect.left) / rect.width, my = 100 * (ev.clientY - rect.top) / rect.height;
    hoverRAF = win.requestAnimationFrame(function () {
      hoverRAF = 0;
      hero.style.setProperty('--r2o-cursor-x', mx + '%');
      hero.style.setProperty('--r2o-cursor-y', my + '%');
    });
  }, { passive: true });
  if (win.IntersectionObserver) new win.IntersectionObserver(function (entries) {
    if (!entries.length) return;
    onscreen = entries[entries.length - 1].isIntersecting; update();
  }, { threshold: 0 }).observe(hero);
  doc.addEventListener('visibilitychange', function () { visible = !doc.hidden; update(); });
  if (win.ResizeObserver) new win.ResizeObserver(relayout).observe(layer);
  else win.addEventListener('resize', relayout, { passive: true });
  if (reduce && reduce.addEventListener) reduce.addEventListener('change', function (e) {
    reduceMotion = e.matches; if (reduceMotion) draw(clock); update();
  });
  resize(); draw(0); update();
})(window, document);
