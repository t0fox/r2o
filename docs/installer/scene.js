const canvas = document.querySelector("canvas");
const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");

const vertex = `
  attribute vec3 position;
  attribute vec4 detail;
  uniform vec3 scene;
  varying vec3 tint;
  varying float opacity;
  varying float byteValue;

  void main() {
    float time = scene.x;
    float seed = detail.x;
    float path = detail.y;
    float depth = 3.75 / (3.75 - position.z);
    gl_Position = vec4(position.xy, -.24 * position.z, 1.);
    gl_PointSize = clamp(scene.y * (.58 + detail.z * .86) * depth, 1., scene.z);

    vec3 cool = vec3(.50, .82, .83);
    vec3 warm = vec3(.84, .64, .36);
    vec3 base = mix(cool, warm, smoothstep(-.22, .38, detail.w));
    // Фаза штриха определяется исходной позицией. Она не сбрасывается при разлёте.
    float wave = pow(max(0., cos(6.283185 * (path - time / 7.5))), 22.);
    float shimmer = .5 + .5 * sin(time * (1.7 + seed * 3.) + seed * 71.);
    tint = mix(base, vec3(.91, .99, .97), wave * .79);
    opacity = clamp(.28 + detail.z * .45 + wave * .42 + shimmer * .14
      + position.z * .10, 0., 1.);
    float beat = floor(time * (4.5 + seed * 3.2) + seed * 53.);
    byteValue = floor(fract(seed * 397.31 + beat * .61803399) * 256.);
  }
`;

const fragment = `
  precision mediump float;
  uniform sampler2D atlas;
  varying vec3 tint;
  varying float opacity;
  varying float byteValue;

  void main() {
    vec2 cell = vec2(mod(byteValue, 16.), floor(byteValue / 16.));
    vec2 sampleAt = (cell + clamp(gl_PointCoord, .02, .98)) / 16.;
    float ink = texture2D(atlas, sampleAt).a * opacity;
    vec2 delta = (gl_PointCoord - .5) * vec2(1., 1.9);
    float aura = max(0., 1. - dot(delta, delta) * 4.);
    float alpha = ink + aura * aura * .075 * opacity;
    gl_FragColor = vec4(tint, alpha);
  }
`;

// Контур пиксельной петли панели.
const outline = [
  [20, 20], [17.5, 20], [17.5, 17.5], [15, 17.5], [15, 15], [12.5, 15],
  [12.5, 12.5], [7.5, 12.5], [7.5, 15], [5, 15], [5, 17.5],
  [2.5, 17.5], [2.5, 22.5], [5, 22.5], [5, 25], [7.5, 25],
  [7.5, 27.5], [12.5, 27.5], [12.5, 25], [15, 25], [15, 22.5],
  [17.5, 22.5], [17.5, 20], [22.5, 20], [22.5, 17.5], [25, 17.5],
  [25, 15], [27.5, 15], [27.5, 12.5], [32.5, 12.5], [32.5, 15],
  [35, 15], [35, 17.5], [37.5, 17.5], [37.5, 22.5], [35, 22.5],
  [35, 25], [32.5, 25], [32.5, 27.5], [27.5, 27.5], [27.5, 25],
  [25, 25], [25, 22.5], [22.5, 22.5], [22.5, 20]
];

function makeAtlas(gl) {
  const sheet = document.createElement("canvas");
  const cell = 64;
  sheet.width = sheet.height = cell * 16;
  const ink = sheet.getContext("2d");
  if (!ink) return false;
  ink.fillStyle = "#fff";
  ink.font = "600 33px ui-monospace, Consolas, monospace";
  ink.textAlign = "center";
  ink.textBaseline = "middle";
  for (let i = 0; i < 256; i++) {
    const value = i.toString(16).toUpperCase().padStart(2, "0");
    ink.fillText(value, (i % 16 + .5) * cell, (Math.floor(i / 16) + .51) * cell);
  }
  gl.bindTexture(gl.TEXTURE_2D, gl.createTexture());
  gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, sheet);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
  return true;
}

function makeParticles() {
  let state = 24053;
  const random = () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 4294967296;
  };
  const particles = [];
  const details = [];
  const point = (x, y, phase, size = 1) => {
    const seed = random();
    particles.push({ x, y, z: (random() - .5) * .22, seed: seed * 97, dx: 0, dy: 0, vx: 0, vy: 0 });
    details.push(seed, phase, random() * size, x);
  };
  const segments = [];
  let perimeter = 0;
  for (let i = 0; i < outline.length; i++) {
    const [x, y] = outline[i];
    const [nextX, nextY] = outline[(i + 1) % outline.length];
    const dx = nextX - x, dy = nextY - y;
    const length = Math.hypot(dx, dy);
    segments.push({ x, y, dx, dy, length, start: perimeter });
    perimeter += length;
  }

  for (const { x, y, dx, dy, length, start } of segments) {
    for (let i = 0; i < Math.ceil(length * 8.4); i++) {
      const along = random();
      const width = (random() + random() - 1) * 3.3;
      const px = (x + dx * along + dy / length * width - 20) / 17;
      const py = (20 - y - dy * along + dx / length * width) / 17;
      point(px, py, (start + along * length) / perimeter);
    }
  }

  const word = document.createElement("canvas");
  word.width = 128;
  word.height = 44;
  const pen = word.getContext("2d", { willReadFrequently: true });
  if (pen) {
    pen.font = "650 34px Unbounded, sans-serif";
    pen.textAlign = "center";
    pen.textBaseline = "middle";
    [..."R2O"].forEach((letter, i) => pen.fillText(letter, 24 + i * 40, 23));
    const mask = pen.getImageData(0, 0, word.width, word.height).data;
    for (let y = 0; y < word.height; y += 2) {
      for (let x = 0; x < word.width; x += 3) {
        if (mask[(y * word.width + x) * 4 + 3] > 170) {
          point((x - 64) / 168, -.63 + (22 - y) / 168, .30 + x / 256, .80);
        }
      }
    }
  }

  return { particles, details: new Float32Array(details) };
}

function start() {
  const gl = canvas.getContext("webgl", { alpha: true, premultipliedAlpha: true });
  if (!gl) return;

  const compile = (type, source) => {
    const shader = gl.createShader(type);
    gl.shaderSource(shader, source);
    gl.compileShader(shader);
    return gl.getShaderParameter(shader, gl.COMPILE_STATUS) ? shader : null;
  };
  const vs = compile(gl.VERTEX_SHADER, vertex);
  const fs = compile(gl.FRAGMENT_SHADER, fragment);
  if (!vs || !fs) return;
  const program = gl.createProgram();
  gl.attachShader(program, vs);
  gl.attachShader(program, fs);
  gl.linkProgram(program);
  if (!gl.getProgramParameter(program, gl.LINK_STATUS) || !makeAtlas(gl)) return;
  gl.useProgram(program);

  const { particles, details } = makeParticles();
  const positions = new Float32Array(particles.length * 3);
  const setup = (name, size, data, usage) => {
    const buffer = gl.createBuffer();
    const location = gl.getAttribLocation(program, name);
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.bufferData(gl.ARRAY_BUFFER, data, usage);
    gl.enableVertexAttribArray(location);
    gl.vertexAttribPointer(location, size, gl.FLOAT, false, 0, 0);
    return buffer;
  };
  setup("detail", 4, details, gl.STATIC_DRAW);
  const buffer = setup("position", 3, positions, gl.DYNAMIC_DRAW);
  gl.enable(gl.BLEND);
  gl.blendFuncSeparate(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA, gl.ONE, gl.ONE_MINUS_SRC_ALPHA);
  gl.clearColor(0, 0, 0, 0);

  const scene = gl.getUniformLocation(program, "scene");
  const limit = gl.getParameter(gl.ALIASED_POINT_SIZE_RANGE)[1];
  const startAt = performance.now();
  let frame = 0, previous = startAt, width = 0, height = 0, cursor = null, sweep = null;

  function draw(now) {
    frame = 0;
    if (gl.isContextLost()) return;
    const still = reducedMotion.matches;
    const seconds = still ? 0 : (now - startAt) / 1000;
    const dt = Math.min(.05, Math.max(0, (now - previous) / 1000));
    previous = now;
    const movement = still ? null : sweep;
    sweep = null;
    const scale = Math.min(width * .74, height * 1.05) / 2;
    const radius = Math.min(58, Math.max(28, Math.min(width, height) * .066));
    const angle = -.10 + Math.sin(seconds * .43) * .16;
    const tilt = -.09 + Math.cos(seconds * .5) * .06;
    const ca = Math.cos(angle), sa = Math.sin(angle), ct = Math.cos(tilt), st = Math.sin(tilt);
    const damping = Math.exp(-8 * dt);

    particles.forEach((p, i) => {
      const x = p.x + Math.sin(seconds * 1.15 + p.seed) * .007;
      const y = p.y + Math.cos(seconds * .91 + p.seed) * .007;
      const z = p.z + Math.sin(seconds * 1.21 - p.seed) * .025;
      const turnedZ = ca * z - sa * x;
      const depth = ct * turnedZ + st * y;
      const zoom = scale * 3.75 / (3.75 - depth);
      const sx = width / 2 + (ca * x + sa * z) * zoom;
      const sy = height * .445 - (ct * y - st * turnedZ) * zoom;

      if (movement) {
        const { from, to } = movement;
        const vx = to.x - from.x, vy = to.y - from.y;
        const dx = sx + p.dx - from.x, dy = sy + p.dy - from.y;
        const along = Math.max(0, Math.min(1, (dx * vx + dy * vy) / Math.max(1, vx * vx + vy * vy)));
        const ax = dx - vx * along, ay = dy - vy * along;
        const distance = Math.hypot(ax, ay);
        if (distance < radius) {
          const force = (1 - distance / radius) ** 1.45 * (150 + radius * 5);
          const direction = p.seed;
          p.vx += (distance > 1 ? ax / distance : Math.cos(direction)) * force;
          p.vy += (distance > 1 ? ay / distance : Math.sin(direction)) * force;
        }
      }
      if (still) {
        p.dx = p.dy = p.vx = p.vy = 0;
      } else {
        p.vx = (p.vx - p.dx * 29 * dt) * damping;
        p.vy = (p.vy - p.dy * 29 * dt) * damping;
        p.dx += p.vx * dt;
        p.dy += p.vy * dt;
      }
      positions[i * 3] = (sx + p.dx) * 2 / width - 1;
      positions[i * 3 + 1] = 1 - (sy + p.dy) * 2 / height;
      positions[i * 3 + 2] = depth;
    });

    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.uniform3f(scene, seconds, Math.max(12, Math.min(canvas.width, canvas.height) * .020), limit);
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.bufferSubData(gl.ARRAY_BUFFER, 0, positions);
    gl.drawArrays(gl.POINTS, 0, particles.length);
    if (!document.hidden && !still) frame = requestAnimationFrame(draw);
  }

  function resize() {
    width = canvas.clientWidth;
    height = canvas.clientHeight;
    if (!width || !height || gl.isContextLost()) return;
    const density = Math.min(devicePixelRatio, 3840 / width, 2160 / height);
    canvas.width = Math.round(width * density);
    canvas.height = Math.round(height * density);
    gl.viewport(0, 0, canvas.width, canvas.height);
    cancelAnimationFrame(frame);
    draw(performance.now());
  }

  const stage = canvas.parentElement;
  function disturb(event) {
    const rect = canvas.getBoundingClientRect();
    const point = { x: event.clientX - rect.left, y: event.clientY - rect.top };
    sweep = { from: sweep?.from ?? cursor ?? point, to: point };
    cursor = point;
  }
  stage.addEventListener("pointerdown", event => {
    cursor = null;
    disturb(event);
  }, { passive: true });
  stage.addEventListener("pointermove", disturb, { passive: true });
  for (const event of ["pointerleave", "pointercancel", "pointerup"]) {
    stage.addEventListener(event, () => { cursor = null; }, { passive: true });
  }
  window.addEventListener("resize", resize);
  reducedMotion.addEventListener("change", resize);
  document.addEventListener("visibilitychange", resize);
  canvas.addEventListener("webglcontextlost", () => {
    cancelAnimationFrame(frame);
    document.documentElement.classList.remove("has-webgl");
  });
  resize();
  document.documentElement.classList.add("has-webgl");
}

try {
  await document.fonts.load("650 34px Unbounded");
} catch {
  // Маска надписи может использовать системный шрифт.
}
start();
