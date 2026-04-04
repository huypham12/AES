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
  xorBytes,
  randomBytes,
} = require("./utils");

class AES {
  constructor(key) {
    const keyBytes = toBytes(key);

    if (
      keyBytes.length !== 16 &&
      keyBytes.length !== 24 &&
      keyBytes.length !== 32
    ) {
      throw new Error("AES key must be exactly 16, 24, or 32 bytes");
    }

    this.keyBytes = Uint8Array.from(keyBytes);
    const { expandedKey, Nr } = keyExpansion(this.keyBytes);
    this.expandedKey = expandedKey;
    this.Nr = Nr;
  }

  encryptBlock(block16) {
    if (block16.length !== 16) throw new Error("Block must be 16 bytes");
    const state = Uint8Array.from(block16);

    // trộn state với khóa bằng cách xor với key được sinh ở keyexpansion
    addRoundKey(state, getRoundKey(this.expandedKey, 0));

    // thực hiện các vòng mã hóa
    for (let round = 1; round < this.Nr; round++) {
      subBytes(state);
      shiftRows(state);
      mixColumns(state);
      addRoundKey(state, getRoundKey(this.expandedKey, round));
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, getRoundKey(this.expandedKey, this.Nr));

    return state;
  }

  decryptBlock(block16) {
    if (block16.length !== 16) throw new Error("Block must be 16 bytes");
    const state = Uint8Array.from(block16);

    addRoundKey(state, getRoundKey(this.expandedKey, this.Nr));

    for (let round = this.Nr - 1; round >= 1; round--) {
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
    // Output = IV (16 bytes) || CBC ciphertext
    const out = new Uint8Array(16 + padded.length);
    out.set(iv, 0);

    let previous = iv;
    for (let offset = 0; offset < padded.length; offset += 16) {
      // Block plaintext đầu tiên sẽ được XOR với IV trước khi mã hóa.
      //Sau đó: Mỗi block tiếp theo sẽ XOR với ciphertext của block trước.
      const block = padded.subarray(offset, offset + 16);
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

    const iv = input.subarray(0, 16);
    const ciphertext = input.subarray(16);
    const out = new Uint8Array(ciphertext.length);

    let previous = iv;
    for (let offset = 0; offset < ciphertext.length; offset += 16) {
      const block = ciphertext.subarray(offset, offset + 16);
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

module.exports = { AES };
