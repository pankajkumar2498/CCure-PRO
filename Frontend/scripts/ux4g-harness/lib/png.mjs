/**
 * A PNG decoder for the screenshots Chrome returns — 8-bit, non-interlaced,
 * greyscale / RGB / RGBA. Enough to compare two captures pixel by pixel
 * without a dependency; anything else is refused rather than guessed at.
 */
import { inflateSync } from "node:zlib";

const SIGNATURE = [137, 80, 78, 71, 13, 10, 26, 10];
const CHANNELS = { 0: 1, 2: 3, 4: 2, 6: 4 };

export function decodePng(buf) {
  for (let i = 0; i < SIGNATURE.length; i += 1) {
    if (buf[i] !== SIGNATURE[i]) throw new Error("not a PNG");
  }
  let pos = 8;
  let width = 0;
  let height = 0;
  let bitDepth = 0;
  let colorType = -1;
  let interlace = 0;
  const idat = [];
  while (pos < buf.length) {
    const len = buf.readUInt32BE(pos);
    const type = buf.toString("ascii", pos + 4, pos + 8);
    const data = buf.subarray(pos + 8, pos + 8 + len);
    if (type === "IHDR") {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      bitDepth = data[8];
      colorType = data[9];
      interlace = data[12];
    } else if (type === "IDAT") {
      idat.push(data);
    } else if (type === "IEND") {
      break;
    }
    pos += 12 + len;
  }
  const channels = CHANNELS[colorType];
  if (bitDepth !== 8 || interlace !== 0 || !channels) {
    throw new Error(
      `unsupported PNG: depth ${bitDepth}, colour type ${colorType}, interlace ${interlace}`,
    );
  }

  const raw = inflateSync(Buffer.concat(idat));
  const stride = width * channels;
  const out = Buffer.alloc(height * stride);
  let prev = Buffer.alloc(stride);
  for (let y = 0; y < height; y += 1) {
    const start = y * (stride + 1);
    const filter = raw[start];
    const line = raw.subarray(start + 1, start + 1 + stride);
    const cur = out.subarray(y * stride, (y + 1) * stride);
    for (let x = 0; x < stride; x += 1) {
      const a = x >= channels ? cur[x - channels] : 0;
      const b = prev[x];
      const c = x >= channels ? prev[x - channels] : 0;
      let v = line[x];
      if (filter === 1) v += a;
      else if (filter === 2) v += b;
      else if (filter === 3) v += (a + b) >> 1;
      else if (filter === 4) {
        const p = a + b - c;
        const pa = Math.abs(p - a);
        const pb = Math.abs(p - b);
        const pc = Math.abs(p - c);
        v += pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
      } else if (filter !== 0) {
        throw new Error(`unsupported PNG filter ${filter}`);
      }
      cur[x] = v & 255;
    }
    prev = cur;
  }
  return { width, height, channels, data: out };
}

/**
 * Pixels whose largest channel difference exceeds `tolerance`, and pixels that
 * differ at all but stay within it. A size or format mismatch is reported as
 * every pixel differing.
 */
export function pixelDelta(bufA, bufB, tolerance) {
  const a = decodePng(bufA);
  const b = decodePng(bufB);
  if (
    a.width !== b.width ||
    a.height !== b.height ||
    a.channels !== b.channels
  ) {
    return {
      beyond: Math.max(a.width * a.height, b.width * b.height),
      within: 0,
      bbox: null,
      size: [
        [a.width, a.height],
        [b.width, b.height],
      ],
    };
  }
  let beyond = 0;
  let within = 0;
  let maxDelta = 0;
  let bbox = null;
  const n = a.channels;
  for (let i = 0, px = 0; i < a.data.length; i += n, px += 1) {
    let d = 0;
    for (let k = 0; k < n; k += 1)
      d = Math.max(d, Math.abs(a.data[i + k] - b.data[i + k]));
    if (!d) continue;
    maxDelta = Math.max(maxDelta, d);
    if (d <= tolerance) {
      within += 1;
      continue;
    }
    beyond += 1;
    const x = px % a.width;
    const y = Math.floor(px / a.width);
    bbox = bbox
      ? [
          Math.min(bbox[0], x),
          Math.min(bbox[1], y),
          Math.max(bbox[2], x),
          Math.max(bbox[3], y),
        ]
      : [x, y, x, y];
  }
  return { beyond, within, maxDelta, bbox };
}
