"use strict";

const { S_BOX } = require("./subBytes");
const { rotWord, subWord } = require("./utils");

const RCON = new Uint8Array([
  0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
]);

function keyExpansion(keyBytes) {
  if (!(keyBytes instanceof Uint8Array) && !Buffer.isBuffer(keyBytes)) {
    throw new TypeError("Key must be a Uint8Array or Buffer");
  }
  if (keyBytes.length !== 16) {
    throw new Error("AES-128 requires a 16-byte key");
  }

  const expanded = new Uint8Array(176);
  expanded.set(keyBytes, 0);
  let bytesGenerated = 16;
  let rconIteration = 1;
  const temp = new Uint8Array(4);

  while (bytesGenerated < 176) {
    for (let i = 0; i < 4; i++) temp[i] = expanded[bytesGenerated - 4 + i];

    if (bytesGenerated % 16 === 0) {
      const rotated = rotWord(temp);
      const substituted = subWord(rotated, S_BOX);
      temp.set(substituted);
      temp[0] ^= RCON[rconIteration++];
    }

    for (let i = 0; i < 4; i++) {
      expanded[bytesGenerated] = expanded[bytesGenerated - 16] ^ temp[i];
      bytesGenerated++;
    }
  }

  return expanded;
}

function getRoundKey(expandedKey, round) {
  const start = round * 16;
  return expandedKey.slice(start, start + 16);
}

module.exports = {
  keyExpansion,
  getRoundKey,
  RCON,
};
