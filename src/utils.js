"use strict";
function toBytes(input) {
  if (Buffer.isBuffer(input)) return Uint8Array.from(input);
  if (input instanceof Uint8Array) return Uint8Array.from(input);
  if (typeof input === "string")
    return Uint8Array.from(Buffer.from(input, "utf8"));
  throw new TypeError("Input must be a Buffer, Uint8Array, or string");
}
function bytesToUtf8(bytes) {
  return Buffer.from(bytes).toString("utf8");
}
function hexToBytes(hex) {
  const clean = hex.replace(/\s+/g, "").toLowerCase();
  if (clean.length % 2 !== 0) throw new Error("Invalid hex string");
  if (!/^[0-9a-f]*$/.test(clean)) throw new Error("Invalid hex string");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error("Invalid hex string");
    out[i] = byte;
  }
  return out;
}
function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
function xorBytes(a, b) {
  if (a.length !== b.length)
    throw new Error("XOR requires equal-length arrays");
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}
function rotWord(word4) {
  return new Uint8Array([word4[1], word4[2], word4[3], word4[0]]);
}
function subWord(word4, sBox) {
  return new Uint8Array([
    sBox[word4[0]],
    sBox[word4[1]],
    sBox[word4[2]],
    sBox[word4[3]],
  ]);
}
function pkcs7Pad(data, blockSize = 16) {
  const remainder = data.length % blockSize;
  const padLen = remainder === 0 ? blockSize : blockSize - remainder;
  const out = new Uint8Array(data.length + padLen);
  out.set(data, 0);
  out.fill(padLen, data.length);
  return out;
}

function pkcs7Unpad(data, blockSize = 16) {
  if (data.length === 0 || data.length % blockSize !== 0) {
    throw new Error("Invalid PKCS#7 padded data length");
  }
  const padLen = data[data.length - 1];
  if (padLen < 1 || padLen > blockSize)
    throw new Error("Invalid PKCS#7 padding");
  for (let i = data.length - padLen; i < data.length; i++) {
    if (data[i] !== padLen) throw new Error("Invalid PKCS#7 padding");
  }
  return data.slice(0, data.length - padLen);
}
function gfMultiply(a, b) {
  let p = 0;
  let aa = a & 0xff;
  let bb = b & 0xff;
  for (let i = 0; i < 8; i++) {
    if (bb & 1) p ^= aa;
    const hiBitSet = aa & 0x80;
    aa = (aa << 1) & 0xff;
    if (hiBitSet) aa ^= 0x1b;
    bb >>= 1;
  }
  return p & 0xff;
}
function randomBytes(length) {
  if (!Number.isInteger(length) || length <= 0) {
    throw new Error("randomBytes length must be a positive integer");
  }
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    out[i] = Math.floor(Math.random() * 256) & 0xff;
  }
  return out;
}

module.exports = {
  toBytes,
  bytesToUtf8,
  hexToBytes,
  bytesToHex,
  xorBytes,
  rotWord,
  subWord,
  pkcs7Pad,
  pkcs7Unpad,
  gfMultiply,
  randomBytes,
};
