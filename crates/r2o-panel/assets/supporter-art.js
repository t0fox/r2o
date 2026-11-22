const tau = 2 * Math.PI;
const { sin, cos, sqrt } = Math;

function dots(ctx, x, y, size, color, alpha) {
  ctx.globalAlpha = alpha;
  ctx.fillStyle = color;
  ctx.fillRect(x - size / 2, y - size / 2, size, size);
}

function glow(ctx, x, y, radius, color, strength) {
  ctx.globalAlpha = strength;
  const light = ctx.createRadialGradient(x, y, 0, x, y, radius);
  light.addColorStop(0, color);
  light.addColorStop(1, "transparent");
  ctx.fillStyle = light;
  ctx.fillRect(x - radius, y - radius, radius * 2, radius * 2);
}

function line(ctx, points, color, alpha, width = 1) {
  ctx.globalAlpha = alpha;
  ctx.strokeStyle = color;
  ctx.lineWidth = width;
  ctx.beginPath();
  for (const [x, y] of points) ctx.lineTo(x, y);
  ctx.stroke();
}

function seeded(seed, count, make) {
  const next = () => {
    seed = (Math.imul(1664525, seed) + 1013904223) >>> 0;
    return seed / 4294967296;
  };
  return Array.from({ length: count }, (_, i) => make(next, i));
}

function orbital({ phase, speed }, { ice, teal, warm, ink }) {
  const rings = [-.73, .42, 1.24].map((angle, i) => {
    const radius = 147 + i * 16;
    return Array.from({ length: 97 }, (_, j) => {
      const a = j * tau / 96;
      const x = radius * cos(a);
      const y = radius * sin(a) * (.27 + i * .055);
      return [x * cos(angle) - y * sin(angle), x * sin(angle) + y * cos(angle)];
    });
  });
  const stars = seeded(914, 105, rand => [rand() * tau, 92 + rand() * 146, rand(), rand()]);
  const surface = seeded(112, 270, rand => {
    const z = 2 * rand() - 1;
    const radius = sqrt(1 - z * z);
    const a = rand() * tau;
    return [radius * cos(a), z, radius * sin(a)];
  });

  return (ctx, t) => {
    t = phase + t * speed;
    glow(ctx, 0, 0, 175, teal, .2);
    for (const [a, r, size, phase] of stars) {
      dots(ctx, cos(a) * r, sin(a) * r * .61, .75 + size * 1.5, ice, .13 + .28 * (.5 + .5 * sin(t + phase * tau)));
    }
    for (const [i, ring] of rings.entries()) {
      line(ctx, ring.slice(48), ice, .37);
      const offset = Math.floor((t * (11 + i * 5)) % 96);
      for (let j = 8; j >= 0; j--) {
        const [x, y] = ring[(offset - j + 192) % 96];
        if (((offset - j + 192) % 96) > 48) glow(ctx, x, y, 9, i === 2 ? warm : ice, .52 - j * .045);
      }
    }

    const radius = 53 + sin(t * 1.4) * 1.8;
    glow(ctx, 0, 0, radius * 1.65, ice, .5);
    ctx.globalAlpha = 1;
    const core = ctx.createRadialGradient(-12, -13, 0, 9, 10, radius * 1.25);
    core.addColorStop(0, ink);
    core.addColorStop(.17, ice);
    core.addColorStop(.53, teal);
    core.addColorStop(1, "#101a20");
    ctx.fillStyle = core;
    ctx.beginPath();
    ctx.arc(0, 0, radius, 0, tau);
    ctx.fill();
    const rotation = t * .43;
    const c = cos(rotation);
    const s = sin(rotation);
    for (const [x, y, z] of surface) {
      const depth = z * c - x * s;
      if (depth > 0) dots(ctx, (x * c + z * s) * radius, y * radius, 1.15, ink, .14 + depth * .47);
    }
    for (const [i, ring] of rings.entries()) {
      line(ctx, ring.slice(0, 49), ice, .65);
      const offset = Math.floor((t * (11 + i * 5)) % 96);
      for (let j = 7; j >= 0; j--) {
        const index = (offset - j + 192) % 96;
        if (index > 48) continue;
        const [x, y] = ring[index];
        glow(ctx, x, y, 12, i === 2 ? warm : ice, .74 - j * .065);
        dots(ctx, x, y, j ? 1.25 : 3.4, ink, .95 - j * .1);
      }
    }
  };
}

function prism({ phase, speed }, { ice, teal, warm, ink, deep }) {
  const corners = 5;
  const vertices = [[0, -132, 0], [0, 135, 0]];
  const faces = [];
  for (let i = 0; i < corners; i++) {
    const a = i * tau / corners;
    const b = a + .23;
    vertices.push([78 * cos(a), -40 + sin(2 * a) * 10, 78 * sin(a)]);
    vertices.push([49 * cos(b), 57 + cos(a) * 12, 49 * sin(b)]);
    const upper = 2 + 2 * i;
    const next = 2 + 2 * ((i + 1) % corners);
    faces.push([0, next, upper], [upper, next, upper + 1], [next, next + 1, upper + 1], [1, upper + 1, next + 1]);
  }
  const motes = seeded(268, 84, rand => [rand() * tau, 76 + rand() * 150, 20 + rand() * 112, rand()]);
  const planes = [[-186, -62], [169, -77], [215, 92], [-145, 112], [-186, -62]];

  return (ctx, t) => {
    t = phase + t * speed;
    glow(ctx, 0, 0, 177, teal, .18);
    for (const [x, y] of planes.slice(0, 4)) dots(ctx, x, y, 3, ice, .55);
    line(ctx, planes, ice, .21);
    line(ctx, [[-215, 48], [-104, 38], [111, -20], [202, -47]], teal, .31);
    line(ctx, [[-198, 59], [-96, 48], [121, -11], [213, -38]], teal, .19);
    for (const [a, r, rise, z] of motes) {
      const p = a + t * (.15 + .27 * z);
      dots(ctx, cos(p) * r, sin(p * 2 + z) * rise, .8 + z * 1.6, z > .91 ? warm : ice, .14 + .53 * z);
    }

    const sy = sin(t * .61), cy = cos(t * .61);
    const tilt = .22 + sin(t * .32) * .12;
    const sx = sin(tilt), cx = cos(tilt);
    const roll = -.23 + sin(t * .45) * .09;
    const sr = sin(roll), cr = cos(roll);
    const points = vertices.map(([x, y, z]) => {
      const x1 = x * cy + z * sy;
      const z1 = z * cy - x * sy;
      const y1 = y * cx - z1 * sx;
      const depth = z1 * cx + y * sx;
      const scale = 460 / (460 - depth);
      return [(x1 * cr - y1 * sr) * scale, (x1 * sr + y1 * cr) * scale, depth];
    });
    const facets = faces.map(face => face.map(i => points[i]));
    facets.sort((a, b) => a.reduce((sum, p) => sum + p[2], 0) - b.reduce((sum, p) => sum + p[2], 0));
    for (const [a, b, c] of facets) {
      const ax = b[0] - a[0], ay = b[1] - a[1];
      const bx = c[0] - a[0], by = c[1] - a[1];
      const light = Math.min(1, Math.abs(ax * by - ay * bx) / 17300);
      const color = (Math.round((a[2] + c[2]) / 36) + 8) % 5 === 1 ? warm : ice;
      const glass = ctx.createLinearGradient(a[0], a[1], c[0] + .01, c[1]);
      glass.addColorStop(0, color);
      glass.addColorStop(.49, teal);
      glass.addColorStop(1, deep);
      ctx.globalAlpha = .24 + light * .59;
      ctx.fillStyle = glass;
      ctx.beginPath();
      ctx.moveTo(a[0], a[1]);
      ctx.lineTo(b[0], b[1]);
      ctx.lineTo(c[0], c[1]);
      ctx.closePath();
      ctx.fill();
      line(ctx, [a, b, c, a], ink, .27 + light * .52, .78);
    }
    const [tip, base] = points;
    glow(ctx, tip[0], tip[1], 24, ice, .66);
    glow(ctx, base[0], base[1], 27, teal, .61);
  };
}

function finale(canvas, path, { ice, teal, warm, ink }) {
  const length = path.getTotalLength();
  const count = 740;
  const flecks = seeded(773, count, (rand, i) => {
    const at = i / count;
    const { x, y } = path.getPointAtLength(length * at);
    return {
      x: (x - 20) * 6.3 + (rand() - .5) * 9,
      y: (y - 20) * 6.3 + (rand() - .5) * 9,
      at,
      drift: [rand() * tau, 76 + rand() * 211],
      delay: rand() * 1.15,
      size: .85 + rand() * 2.25,
      color: rand() > .8 ? warm : ice,
      shine: .38 + rand() * .54,
      dx: 0, dy: 0,
    };
  });
  let point = null;
  let last = 0;

  canvas.addEventListener("pointermove", event => {
    if (event.pointerType !== "mouse") return;
    const rect = canvas.getBoundingClientRect();
    const scale = artScale(canvas, rect.width, rect.height);
    if (!scale) return;
    point = [(event.clientX - rect.left - rect.width / 2) / scale,
      (event.clientY - rect.top - rect.height / 2) / scale];
  });
  canvas.addEventListener("pointerleave", () => { point = null; });

  return (ctx, t, still) => {
    const elapsed = last ? Math.max(.016, Math.min(.05, t - last)) : .033;
    last = t;
    const assembling = t < 3.5;
    const cursor = still || assembling ? null : point;
    const ease = still ? 1 : 1 - Math.exp(-elapsed / (cursor ? .044 : .068));
    const pulse = (t / 7.5) % 1;
    glow(ctx, 0, 0, 115, teal, .15);

    for (const fleck of flecks) {
      const { x, y, drift: [angle, distance], delay, size, color, shine, at } = fleck;
      let tx = 0, ty = 0;
      if (cursor) {
        const px = x - cursor[0], py = y - cursor[1];
        const radius = Math.hypot(px, py) || 1;
        if (radius < 126) {
          const force = (65 + size * 13.5) * Math.pow(1 - radius / 126, 1.35) / radius;
          tx = px * force;
          ty = py * force;
        }
      }
      fleck.dx += (tx - fleck.dx) * ease;
      fleck.dy += (ty - fleck.dy) * ease;
      let px = x + fleck.dx, py = y + fleck.dy;
      if (assembling) {
        const remaining = Math.max(0, Math.min(1, 1 - (t - delay) / 2.35));
        const drift = remaining * remaining * distance;
        px += cos(angle + remaining * 2) * drift;
        py += sin(angle + remaining * 2) * drift * .38;
      }
      const lit = !still && (at - pulse + 1) % 1 < .07;
      dots(ctx, px, py,
        lit ? size * 1.16 : size, lit ? ink : color, lit ? .96 : shine);
    }
  };
}

function artScale(canvas, width, height) {
  return Math.min(width / 570, height / Number(canvas.dataset.artHeight || 368));
}

export const art = { orbital, prism, finale };

const times = new WeakMap();
export const artTime = canvas => times.get(canvas) ?? 0;

export function playArt(dialog, scenes) {
  const preference = matchMedia("(prefers-reduced-motion: reduce)");
  const pending = new Set();
  let frame = 0;
  let last = 0;
  const active = new Map();
  for (const [canvas, paint, start = artTime(canvas)] of scenes) {
    const ctx = canvas.getContext("2d");
    if (ctx) active.set(canvas, { ctx, paint, t: start, visible: false });
  }

  function schedule() {
    if (!frame && !document.hidden && pending.size) frame = requestAnimationFrame(draw);
  }

  function draw(now) {
    frame = 0;
    const dt = last ? now - last : 0;
    if (dt > 0 && dt < 31) {
      schedule();
      return;
    }
    last = now;
    const step = Math.min(dt, 40) / 1000;
    for (const canvas of pending) {
      const scene = active.get(canvas);
      const { ctx, paint } = scene;
      const width = canvas.width;
      const height = canvas.height;
      const scale = artScale(canvas, width, height);
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.clearRect(0, 0, width, height);
      ctx.setTransform(scale, 0, 0, scale, width / 2, height / 2);
      times.set(canvas, scene.t);
      paint(ctx, preference.matches ? 4 : scene.t, preference.matches);
      if (preference.matches) pending.delete(canvas);
      else scene.t += step;
    }
    schedule();
  }

  const observer = new IntersectionObserver(entries => {
    for (const { target, isIntersecting } of entries) {
      const scene = active.get(target);
      scene.visible = isIntersecting;
      if (isIntersecting) pending.add(target);
      else pending.delete(target);
    }
    schedule();
  }, { root: dialog });
  const sizes = new ResizeObserver(entries => {
    for (const { target, contentRect: { width, height } } of entries) {
      if (!(width && height)) continue;
      const ratio = Math.min(devicePixelRatio, 1.5);
      target.width = Math.round(width * ratio);
      target.height = Math.round(height * ratio);
      const scene = active.get(target);
      if (scene.visible) pending.add(target);
    }
    schedule();
  });
  for (const canvas of active.keys()) {
    observer.observe(canvas);
    sizes.observe(canvas);
  }

  function onVisibility() {
    if (document.hidden) {
      cancelAnimationFrame(frame);
      frame = 0;
      last = 0;
    } else schedule();
  }
  function onPreference() {
    for (const [canvas, scene] of active) {
      if (scene.visible) pending.add(canvas);
    }
    schedule();
  }

  document.addEventListener("visibilitychange", onVisibility);
  preference.addEventListener("change", onPreference);
  return () => {
    observer.disconnect();
    sizes.disconnect();
    cancelAnimationFrame(frame);
    preference.removeEventListener("change", onPreference);
    document.removeEventListener("visibilitychange", onVisibility);
  };
}
