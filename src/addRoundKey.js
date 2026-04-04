"use strict";

// thực hiện phép XOR giữa state và roundKey để thêm key vào state trong mỗi vòng của AES. Đây là bước quan trọng để đảm bảo tính bảo mật của thuật toán.
function addRoundKey(state, roundKey) {
  if (roundKey.length !== 16) throw new Error("Round key must be 16 bytes");
  for (let i = 0; i < 16; i++) state[i] ^= roundKey[i];
  return state;
}

module.exports = { addRoundKey };
