// Draws the extension icons (a shield with a keyhole) and writes them as PNGs into src/icons.
//   node scripts/make-icons.js
// Everything is computed here, so the icons need no image editor and no dependencies.
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const { crc32 } = require('./lib/crc32.js');

const SIZES = [16, 32, 48, 128];
const TOP = [14, 165, 233]; // sky blue
const BOTTOM = [79, 70, 229]; // indigo
const SUPERSAMPLE = 4;

function bezier(p0, p1, p2, steps) {
  const points = [];
  for (let i = 1; i <= steps; i++) {
    const t = i / steps;
    const a = (1 - t) * (1 - t);
    const b = 2 * (1 - t) * t;
    const c = t * t;
    points.push([a * p0[0] + b * p1[0] + c * p2[0], a * p0[1] + b * p1[1] + c * p2[1]]);
  }
  return points;
}

// The shield outline in a 0..1 square: flat shoulders, straight sides, a curved point at the bottom.
const SHIELD = (() => {
  const right = [[0.5, 0.06], [0.84, 0.17], [0.84, 0.5]];
  const rightCurve = bezier([0.84, 0.5], [0.84, 0.78], [0.5, 0.95], 28);
  const leftCurve = bezier([0.5, 0.95], [0.16, 0.78], [0.16, 0.5], 28);
  return [...right, ...rightCurve, ...leftCurve, [0.16, 0.17]];
})();

const KEYHOLE_STEM = [[0.455, 0.5], [0.545, 0.5], [0.595, 0.72], [0.405, 0.72]];

function inPolygon(x, y, polygon) {
  let inside = false;
  for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i++) {
    const [xi, yi] = polygon[i];
    const [xj, yj] = polygon[j];
    if (yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) inside = !inside;
  }
  return inside;
}

function inKeyhole(x, y) {
  const dx = x - 0.5;
  const dy = y - 0.43;
  return dx * dx + dy * dy <= 0.115 * 0.115 || inPolygon(x, y, KEYHOLE_STEM);
}

function render(size) {
  const pixels = Buffer.alloc(size * size * 4);
  const samples = SUPERSAMPLE * SUPERSAMPLE;
  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      let shield = 0;
      let hole = 0;
      for (let sy = 0; sy < SUPERSAMPLE; sy++) {
        for (let sx = 0; sx < SUPERSAMPLE; sx++) {
          const x = (px + (sx + 0.5) / SUPERSAMPLE) / size;
          const y = (py + (sy + 0.5) / SUPERSAMPLE) / size;
          if (inPolygon(x, y, SHIELD)) {
            shield++;
            if (inKeyhole(x, y)) hole++;
          }
        }
      }
      const t = Math.min(1, Math.max(0, (py / size - 0.06) / 0.89));
      const base = TOP.map((c, i) => c + (BOTTOM[i] - c) * t);
      const white = hole / samples;
      const color = base.map((c) => c + (255 - c) * (white / Math.max(shield / samples, 1e-6)));
      const o = (py * size + px) * 4;
      pixels[o] = Math.round(color[0]);
      pixels[o + 1] = Math.round(color[1]);
      pixels[o + 2] = Math.round(color[2]);
      pixels[o + 3] = Math.round((shield / samples) * 255);
    }
  }
  return pixels;
}

function chunk(type, data) {
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const out = Buffer.alloc(body.length + 8);
  out.writeUInt32BE(data.length, 0);
  body.copy(out, 4);
  out.writeUInt32BE(crc32(body), body.length + 4);
  return out;
}

function png(size, rgba) {
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header[8] = 8; // bit depth
  header[9] = 6; // RGBA
  const rows = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) {
    rows[y * (size * 4 + 1)] = 0; // no filter
    rgba.copy(rows, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', header),
    chunk('IDAT', zlib.deflateSync(rows, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

function makeIcons(outDir) {
  fs.mkdirSync(outDir, { recursive: true });
  const written = [];
  for (const size of SIZES) {
    const file = path.join(outDir, `icon-${size}.png`);
    fs.writeFileSync(file, png(size, render(size)));
    written.push(file);
  }
  return written;
}

if (require.main === module) {
  const files = makeIcons(path.join(__dirname, '..', 'src', 'icons'));
  console.log('wrote ' + files.map((f) => path.basename(f)).join(', '));
}

module.exports = { makeIcons, png, render, SIZES };
