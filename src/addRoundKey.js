"use strict";

function addRoundKey(state, roundKey) {
  if (roundKey.length !== 16) throw new Error("Round key must be 16 bytes");
  for (let i = 0; i < 16; i++) state[i] ^= roundKey[i];
  return state;
}

module.exports = { addRoundKey };
