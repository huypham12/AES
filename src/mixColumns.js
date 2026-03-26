"use strict";

const { gfMultiply } = require("./utils");
function mixColumns(state) {
  const out = new Uint8Array(16);
  for (let col = 0; col < 4; col++) {
    const i = 4 * col;
    const a0 = state[i];
    const a1 = state[i + 1];
    const a2 = state[i + 2];
    const a3 = state[i + 3];

    out[i] = gfMultiply(a0, 0x02) ^ gfMultiply(a1, 0x03) ^ a2 ^ a3;
    out[i + 1] = a0 ^ gfMultiply(a1, 0x02) ^ gfMultiply(a2, 0x03) ^ a3;
    out[i + 2] = a0 ^ a1 ^ gfMultiply(a2, 0x02) ^ gfMultiply(a3, 0x03);
    out[i + 3] = gfMultiply(a0, 0x03) ^ a1 ^ a2 ^ gfMultiply(a3, 0x02);
  }
  state.set(out);
  return state;
}

function invMixColumns(state) {
  const out = new Uint8Array(16);
  for (let col = 0; col < 4; col++) {
    const i = 4 * col;
    const a0 = state[i];
    const a1 = state[i + 1];
    const a2 = state[i + 2];
    const a3 = state[i + 3];

    out[i] =
      gfMultiply(a0, 0x0e) ^
      gfMultiply(a1, 0x0b) ^
      gfMultiply(a2, 0x0d) ^
      gfMultiply(a3, 0x09);
    out[i + 1] =
      gfMultiply(a0, 0x09) ^
      gfMultiply(a1, 0x0e) ^
      gfMultiply(a2, 0x0b) ^
      gfMultiply(a3, 0x0d);
    out[i + 2] =
      gfMultiply(a0, 0x0d) ^
      gfMultiply(a1, 0x09) ^
      gfMultiply(a2, 0x0e) ^
      gfMultiply(a3, 0x0b);
    out[i + 3] =
      gfMultiply(a0, 0x0b) ^
      gfMultiply(a1, 0x0d) ^
      gfMultiply(a2, 0x09) ^
      gfMultiply(a3, 0x0e);
  }
  state.set(out);
  return state;
}

module.exports = {
  mixColumns,
  invMixColumns,
};
