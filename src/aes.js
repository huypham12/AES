"use strict";

const { keyExpansion, getRoundKey } = require("./keyExpansion");
const { subBytes, invSubBytes } = require("./subBytes");
const { shiftRows, invShiftRows } = require("./shiftRows");
const { mixColumns, invMixColumns } = require("./mixColumns");
const { addRoundKey } = require("./addRoundKey");
const {
  pkcs7Pad,
  pkcs7Unpad,
  toBytes,
  hexToBytes,
  xorBytes,
  randomBytes,
} = require("./utils");

class AES128 {
  constructor(key) {
    let keyBytes;

    if (typeof key === "string") {
      const clean = key.replace(/\s+/g, "");
      const isHex = /^[0-9a-fA-F]+$/.test(clean);

      if (isHex && clean.length === 32) {
        keyBytes = hexToBytes(clean);
      } else {
        keyBytes = toBytes(key);
      }
    } else {
      keyBytes = toBytes(key);
    }

    if (keyBytes.length !== 16) {
      throw new Error("AES-128 key must be exactly 16 bytes");
    }

    this.keyBytes = Uint8Array.from(keyBytes);
    this.expandedKey = keyExpansion(this.keyBytes);
  }

  encryptBlock(block16) {
    if (block16.length !== 16) throw new Error("Block must be 16 bytes");
    const state = Uint8Array.from(block16);

    addRoundKey(state, getRoundKey(this.expandedKey, 0));

    for (let round = 1; round <= 9; round++) {
      subBytes(state);
      shiftRows(state);
      mixColumns(state);
      addRoundKey(state, getRoundKey(this.expandedKey, round));
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, getRoundKey(this.expandedKey, 10));

    return state;
  }

  decryptBlock(block16) {
    if (block16.length !== 16) throw new Error("Block must be 16 bytes");
    const state = Uint8Array.from(block16);

    addRoundKey(state, getRoundKey(this.expandedKey, 10));

    for (let round = 9; round >= 1; round--) {
      invShiftRows(state);
      invSubBytes(state);
      addRoundKey(state, getRoundKey(this.expandedKey, round));
      invMixColumns(state);
    }

    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, getRoundKey(this.expandedKey, 0));

    return state;
  }

  encryptBytes(bytes) {
    const input = toBytes(bytes);
    const padded = pkcs7Pad(input, 16);
    const iv = randomBytes(16);
    const out = new Uint8Array(16 + padded.length);
    out.set(iv, 0);

    let previous = iv;
    for (let offset = 0; offset < padded.length; offset += 16) {
      const block = padded.slice(offset, offset + 16);
      const xored = xorBytes(block, previous);
      const encrypted = this.encryptBlock(xored);
      out.set(encrypted, 16 + offset);
      previous = encrypted;
    }
    return out;
  }

  decryptBytes(bytes) {
    const input = toBytes(bytes);
    if (input.length < 32 || input.length % 16 !== 0) {
      throw new Error(
        "Ciphertext length must be at least 32 bytes and a multiple of 16 (includes IV)",
      );
    }

    const iv = input.slice(0, 16);
    const ciphertext = input.slice(16);
    const out = new Uint8Array(ciphertext.length);

    let previous = iv;
    for (let offset = 0; offset < ciphertext.length; offset += 16) {
      const block = ciphertext.slice(offset, offset + 16);
      const decrypted = this.decryptBlock(block);
      const plainBlock = xorBytes(decrypted, previous);
      out.set(plainBlock, offset);
      previous = block;
    }

    return pkcs7Unpad(out, 16);
  }

  encryptText(text) {
    return this.encryptBytes(toBytes(text));
  }

  decryptToText(bytes) {
    return Buffer.from(this.decryptBytes(bytes)).toString("utf8");
  }
}

module.exports = { AES128 };
