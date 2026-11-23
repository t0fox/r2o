const canvas = document.querySelector("canvas");
const reduction = matchMedia("(prefers-reduced-motion: reduce)");

const vertex = `
  attribute vec3 position;
  attribute vec3 normal;
  attribute float advance;
  uniform vec2 angle;
  uniform float aspect;
  varying vec3 vNormal;
  varying vec3 vPosition;
  varying vec2 vPath;

  void main() {
    float ca = cos(angle.x), sa = sin(angle.x);
    float cb = cos(angle.y), sb = sin(angle.y);
    mat3 tilt = mat3(1., 0., 0., 0., ca, sa, 0., -sa, ca);
    mat3 turn = mat3(cb, 0., -sb, 0., 1., 0., sb, 0., cb);
    vec3 p = tilt * turn * position;
    vNormal = tilt * turn * normal;
    vPosition = p;
    vPath = vec2(position.x, advance);
    float framing = min(aspect * .72, 1.04);
    float perspective = 3.7 / (3.7 - p.z);
    gl_Position = vec4(p.xy * vec2(framing / aspect, framing) * perspective
      + vec2(0., .11), -.24 * p.z, 1.);
  }
`;

const fragment = `
  precision highp float;
  uniform float time;
  varying vec3 vNormal;
  varying vec3 vPosition;
  varying vec2 vPath;

  void main() {
    vec3 n = normalize(vNormal);
    vec3 view = normalize(vec3(0., 0., 3.7) - vPosition);
    vec3 cool = vec3(.50, .82, .83);
    vec3 warm = vec3(.84, .64, .36);
    vec3 metal = mix(cool, warm, smoothstep(-.10, .28, vPath.x));
    vec3 light = normalize(vec3(-.75, 1., 1.3));
    vec3 amberLight = normalize(vec3(.85, -.75, .9));
    float diffuse = max(dot(n, light), 0.);
    float bronze = max(dot(n, amberLight), 0.);
    float rim = pow(1. - max(dot(n, view), 0.), 2.8);
    float polish = pow(max(dot(n, normalize(light + view)), 0.), 62.);
    float glow = pow(max(dot(n, normalize(amberLight + view)), 0.), 18.);
    float stroke = .5 + .5 * cos(6.283185 * (vPath.y - time * .10));
    vec3 reflected = mix(cool, warm, smoothstep(-.65, .7, n.x));
    float highlight = exp(-pow((n.y - .56) * 8., 2.));
    vec3 rgb = metal * (.09 + .44 * diffuse + .25 * bronze)
      + reflected * (.28 * rim + .11 * highlight + .44 * pow(stroke, 18.))
      + vec3(.78, .93, .95) * polish * .65 + warm * glow * .33;
    gl_FragColor = vec4(rgb, 1.);
  }
`;

// Контур штатного знака панели. Скругляем повороты перед построением трубы.
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

function makeTube() {
  const count = outline.length;
  const samples = [];
  const corner = 0.32;

  for (let i = 0; i < count; i++) {
    const before = outline[(i + count - 1) % count];
    const after = outline[(i + 1) % count];
    const [x, y] = outline[i];
    for (let step = 0; step <= 6; step++) {
      const t = step / 6;
      const start = (1 - t) ** 2 * corner;
      const end = t ** 2 * corner;
      samples.push([
        (x + (before[0] - x) * start + (after[0] - x) * end - 20) / 17,
        (20 - y - (before[1] - y) * start - (after[1] - y) * end) / 17,
      ]);
    }
  }

  const sides = 24;
  const vertices = [];
  const triangles = [];
  for (let ring = 0; ring <= samples.length; ring++) {
    const i = ring % samples.length;
    const [x, y] = samples[i];
    const before = samples[(i + samples.length - 1) % samples.length];
    const after = samples[(i + 1) % samples.length];
    const dx = after[0] - before[0];
    const dy = after[1] - before[1];
    const tangent = Math.hypot(dx, dy);
    for (let side = 0; side < sides; side++) {
      const a = side * Math.PI * 2 / sides;
      const nx = -dy / tangent * Math.cos(a);
      const ny = dx / tangent * Math.cos(a);
      const nz = Math.sin(a);
      vertices.push(x + nx * .048, y + ny * .048, nz * .087, nx, ny, nz, ring / samples.length);
      if (ring > 0) {
        const first = (ring - 1) * sides + side;
        const second = (ring - 1) * sides + (side + 1) % sides;
        triangles.push(first, second, first + sides, second, second + sides, first + sides);
      }
    }
  }
  return [new Float32Array(vertices), new Uint16Array(triangles)];
}

function start() {
  const gl = canvas.getContext("webgl", { alpha: true, antialias: true });
  if (!gl) return;

  const makeShader = (type, source) => {
    const shader = gl.createShader(type);
    gl.shaderSource(shader, source);
    gl.compileShader(shader);
    return gl.getShaderParameter(shader, gl.COMPILE_STATUS) ? shader : null;
  };
  const vs = makeShader(gl.VERTEX_SHADER, vertex);
  const fs = makeShader(gl.FRAGMENT_SHADER, fragment);
  if (!vs || !fs) return;
  const program = gl.createProgram();
  gl.attachShader(program, vs);
  gl.attachShader(program, fs);
  gl.linkProgram(program);
  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) return;
  gl.useProgram(program);

  const [vertices, triangles] = makeTube();
  gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
  gl.bufferData(gl.ARRAY_BUFFER, vertices, gl.STATIC_DRAW);
  for (const [name, size, offset] of [["position", 3, 0], ["normal", 3, 12], ["advance", 1, 24]]) {
    const location = gl.getAttribLocation(program, name);
    gl.enableVertexAttribArray(location);
    gl.vertexAttribPointer(location, size, gl.FLOAT, false, 28, offset);
  }
  gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, gl.createBuffer());
  gl.bufferData(gl.ELEMENT_ARRAY_BUFFER, triangles, gl.STATIC_DRAW);
  gl.enable(gl.DEPTH_TEST);
  gl.clearColor(0, 0, 0, 0);

  const angle = gl.getUniformLocation(program, "angle");
  const aspect = gl.getUniformLocation(program, "aspect");
  const time = gl.getUniformLocation(program, "time");
  let frame = 0;

  function draw(ms) {
    frame = 0;
    const seconds = reduction.matches ? 0 : ms / 1000;
    gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);
    gl.uniform2f(angle, -.22 + Math.sin(seconds * .64) * .13, -.18 + Math.sin(seconds * .46) * .42);
    gl.uniform1f(time, seconds);
    gl.drawElements(gl.TRIANGLES, triangles.length, gl.UNSIGNED_SHORT, 0);
    if (!document.hidden && !reduction.matches) frame = requestAnimationFrame(draw);
  }

  function resize() {
    if (!canvas.clientWidth || !canvas.clientHeight) return;
    const density = Math.min(devicePixelRatio, 3840 / canvas.clientWidth, 2160 / canvas.clientHeight);
    canvas.width = Math.round(canvas.clientWidth * density);
    canvas.height = Math.round(canvas.clientHeight * density);
    gl.viewport(0, 0, canvas.width, canvas.height);
    gl.uniform1f(aspect, canvas.width / canvas.height);
    cancelAnimationFrame(frame);
    draw(performance.now());
  }

  window.addEventListener("resize", resize);
  reduction.addEventListener("change", resize);
  document.addEventListener("visibilitychange", resize);
  canvas.addEventListener("webglcontextlost", () => {
    cancelAnimationFrame(frame);
    document.documentElement.classList.remove("has-webgl");
  });
  resize();
  document.documentElement.classList.add("has-webgl");
}

start();
