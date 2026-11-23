const canvas = document.querySelector("canvas");
const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");

const vertex = `
  attribute vec3 home;
  attribute vec3 flight;
  attribute vec3 detail;
  uniform vec4 scene;
  uniform vec2 pointer;
  uniform float repel;
  varying vec3 tint;
  varying float opacity;
  varying float byteValue;

  void main() {
    float time = scene.x;
    float phase = mod(time, 12.);
    float seed = detail.x;
    float path = detail.y;
    float delay = seed * .64;
    float outward = smoothstep(2.35 + delay, 4.90 + delay, phase);
    float inward = smoothstep(6.10 + delay, 10.95 + delay, phase);
    float spread = outward * (1. - inward);
    vec3 drift = vec3(sin(time * 1.16 + seed * 58.), cos(time * .91 + seed * 107.),
      sin(time * 1.28 + seed * 91.));
    vec3 turn = vec3(-flight.y, flight.x * .55, sin(path * 32.));
    vec3 p = home + flight * spread + turn * sin(phase * .91 + seed * 9.) * spread * .23
      + drift * (.012 + spread * .095);

    vec2 delta = p.xy - pointer;
    float distance = length(delta);
    float force = pow(max(0., 1. - distance / .59), 1.35) * repel;
    p.xy += delta / max(.022, distance) * force * .29;
    p.z += force * .30;

    float angle = -.12 + sin(time * .43) * .31;
    float tilt = -.12 + cos(time * .5) * .11;
    float ca = cos(angle), sa = sin(angle), ct = cos(tilt), st = sin(tilt);
    p = vec3(ca * p.x + sa * p.z, p.y, ca * p.z - sa * p.x);
    p = vec3(p.x, ct * p.y - st * p.z, ct * p.z + st * p.y);

    float depth = 3.75 / (3.75 - p.z);
    float framing = min(scene.y * .74, 1.05);
    gl_Position = vec4(p.xy * vec2(framing / scene.y, framing) * depth + vec2(0., .11), -.24 * p.z, 1.);
    gl_PointSize = clamp(scene.z * (.62 + detail.z * .88) * depth, 1., scene.w);

    vec3 cool = vec3(.50, .82, .83);
    vec3 warm = vec3(.84, .64, .36);
    vec3 base = mix(cool, warm, smoothstep(-.22, .38, home.x));
    // Фаза штриха определяется исходной позицией. Она не сбрасывается при разлёте.
    float wave = pow(max(0., cos(6.283185 * (path - time / 7.5))), 22.);
    float shimmer = .5 + .5 * sin(time * (1.7 + seed * 3.) + seed * 71.);
    tint = mix(base, vec3(.91, .99, .97), wave * .79 + force * .14);
    opacity = clamp(.28 + detail.z * .45 + wave * .42 + shimmer * .14
      + p.z * .10 - spread * .08, 0., 1.);
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
  const points = [];
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
      const z = (random() - .5) * .24;
      const velocity = random() * .49 + .20;
      const fx = px * velocity + (random() - .5) * 1.12;
      const fy = py * velocity + (random() - .5) * 1.50;
      const fz = (random() - .5) * 1.56;
      points.push(px, py, z, fx, fy, fz, random(), (start + along * length) / perimeter, random());
    }
  }
  return new Float32Array(points);
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

  const data = makeParticles();
  gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
  gl.bufferData(gl.ARRAY_BUFFER, data, gl.STATIC_DRAW);
  for (const [name, offset] of [["home", 0], ["flight", 12], ["detail", 24]]) {
    const location = gl.getAttribLocation(program, name);
    gl.enableVertexAttribArray(location);
    gl.vertexAttribPointer(location, 3, gl.FLOAT, false, 36, offset);
  }
  gl.enable(gl.BLEND);
  gl.blendFuncSeparate(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA, gl.ONE, gl.ONE_MINUS_SRC_ALPHA);
  gl.clearColor(0, 0, 0, 0);

  const scene = gl.getUniformLocation(program, "scene");
  const pointer = gl.getUniformLocation(program, "pointer");
  const repel = gl.getUniformLocation(program, "repel");
  const limit = gl.getParameter(gl.ALIASED_POINT_SIZE_RANGE)[1];
  const startAt = performance.now();
  let frame = 0, push = 0, target = 0, x = 0, y = 0;

  function draw(now) {
    frame = 0;
    if (gl.isContextLost()) return;
    const seconds = reducedMotion.matches ? 0 : (now - startAt) / 1000;
    const aspect = canvas.width / canvas.height;
    const size = Math.max(12, Math.min(canvas.width, canvas.height) * .020);
    push += (target - push) * .16;
    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.uniform4f(scene, seconds, aspect, size, limit);
    gl.uniform2f(pointer, x, y);
    gl.uniform1f(repel, reducedMotion.matches ? 0 : push);
    gl.drawArrays(gl.POINTS, 0, data.length / 9);
    if (!document.hidden && !reducedMotion.matches) frame = requestAnimationFrame(draw);
  }

  function resize() {
    const { clientWidth: width, clientHeight: height } = canvas;
    if (!width || !height || gl.isContextLost()) return;
    const density = Math.min(devicePixelRatio, 3840 / width, 2160 / height);
    canvas.width = Math.round(width * density);
    canvas.height = Math.round(height * density);
    gl.viewport(0, 0, canvas.width, canvas.height);
    cancelAnimationFrame(frame);
    draw(performance.now());
  }

  const stage = canvas.parentElement;
  stage.addEventListener("pointermove", event => {
    const rect = canvas.getBoundingClientRect();
    const aspect = rect.width / rect.height;
    const scale = Math.min(aspect * .74, 1.05);
    x = ((event.clientX - rect.left) * 2 / rect.width - 1) * aspect / scale;
    y = (1 - (event.clientY - rect.top) * 2 / rect.height - .11) / scale;
    target = 1;
  }, { passive: true });
  stage.addEventListener("pointerleave", () => { target = 0; });
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

start();
