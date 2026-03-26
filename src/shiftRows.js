"use strict";

function shiftRows(state) {
  const out = new Uint8Array(16);
  for (let row = 0; row < 4; row++) {
    for (let col = 0; col < 4; col++) {
      out[row + 4 * col] = state[row + 4 * ((col + row) % 4)];
    }
  }
  state.set(out);
  return state;
}

function invShiftRows(state) {
  const out = new Uint8Array(16);
  for (let row = 0; row < 4; row++) {
    for (let col = 0; col < 4; col++) {
      out[row + 4 * col] = state[row + 4 * ((col - row + 4) % 4)];
    }
  }
  state.set(out);
  return state;
}

module.exports = {
  shiftRows,
  invShiftRows,
};
