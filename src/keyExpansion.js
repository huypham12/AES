"use strict";

const { S_BOX } = require("./subBytes");
const { rotWord, subWord } = require("./utils");

// Round Constant: Rcon[i] = 2^(i-1) trong GF(2^8)
// phá tính đối xứng của key
const RCON = new Uint8Array([
  0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
]);

function keyExpansion(keyBytes) {
  if (!(keyBytes instanceof Uint8Array) && !Buffer.isBuffer(keyBytes)) {
    throw new TypeError("Key must be a Uint8Array or Buffer");
  }

  const Nk = keyBytes.length / 4;
  if (Nk !== 4 && Nk !== 6 && Nk !== 8) {
    throw new Error("Key must be 16, 24, or 32 bytes long");
  }

  const Nr = Nk + 6;
  const totalWords = 4 * (Nr + 1);
  const expanded = new Uint8Array(totalWords * 4);
  expanded.set(keyBytes, 0);

  let rconIteration = 1;
  const temp = new Uint8Array(4);

  for (let i = Nk; i < totalWords; i++) {
    for (let j = 0; j < 4; j++) temp[j] = expanded[(i - 1) * 4 + j];

    if (i % Nk === 0) {
      const rotated = rotWord(temp);
      const substituted = subWord(rotated, S_BOX);
      temp.set(substituted);
      temp[0] ^= RCON[rconIteration++];
    } else if (Nk > 6 && i % Nk === 4) {
      const substituted = subWord(temp, S_BOX);
      temp.set(substituted);
    }

    for (let j = 0; j < 4; j++) {
      expanded[i * 4 + j] = expanded[(i - Nk) * 4 + j] ^ temp[j];
    }
  }

  return { expandedKey: expanded, Nr };
}

// cắt cái expanded key đã được tạo ra thành round key cho từng round, mỗi round key có 16 byte
function getRoundKey(expandedKey, round) {
  const start = round * 16;
  return expandedKey.subarray(start, start + 16); // subarray trả về một phần của mảng mà không tạo bản sao mới, kiểu nó "trỏ" đến mảng gốc, khi thay đổi subarray thì expandedKey cũng thay đổi theo
}

module.exports = {
  keyExpansion,
  getRoundKey,
  RCON,
};
