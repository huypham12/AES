"use strict";

// chuyển đổi input thành Uint8Array (byte array, mỗi ptu 0-255)
function toBytes(input) {
  if (Buffer.isBuffer(input)) return Uint8Array.from(input);
  if (input instanceof Uint8Array) return Uint8Array.from(input);
  if (typeof input === "string")
    return Uint8Array.from(Buffer.from(input, "utf8")); // String → (UTF-8 encode) → Buffer → (copy) → Uint8Array
  throw new TypeError("Input must be a Buffer, Uint8Array, or string");
}

// chuyển byte array thành string bằng UTF-8 decode
function bytesToUtf8(bytes) {
  return Buffer.from(bytes).toString("utf8");
}

// chuyển hex string thành byte array, ví dụ "0x01 0x02 0x03 0x04" thành Uint8Array [1, 2, 3, 4] bản chất là 00000001, 00000010, 00000011, 00000100
function hexToBytes(hex) {
  const clean = hex.replace(/\s+/g, "").toLowerCase(); // xóa khoảng trắng và chuyển thành chữ thường để chuẩn hóa input
  if (clean.length % 2 !== 0) throw new Error("Invalid hex string"); // hex string phải có số lượng ký tự chẵn vì mỗi byte được biểu diễn bằng 2 ký tự hex
  if (!/^[0-9a-f]*$/.test(clean)) throw new Error("Invalid hex string"); // kiểm tra chỉ chứa các ký tự hex hợp lệ (0-9, a-f)
  const out = new Uint8Array(clean.length / 2); // mỗi byte được biểu diễn bằng 2 ký tự hex
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(clean.slice(i * 2, i * 2 + 2), 16); // lấy từng cặp 2 ký tự hex và chuyển thành số nguyên (byte)
    if (Number.isNaN(byte)) throw new Error("Invalid hex string");
    out[i] = byte;
  }
  return out;
}

// chuyển byte sang hex string, rồi nối lại
function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// xor từng bit giữa hai mảng
function xorBytes(a, b) {
  if (a.length !== b.length)
    throw new Error("XOR requires equal-length arrays");
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

// xoay một word 4 byte sang trái, ví dụ [0x01, 0x02, 0x03, 0x04] thành [0x02, 0x03, 0x04, 0x01]
function rotWord(word4) {
  return new Uint8Array([word4[1], word4[2], word4[3], word4[0]]);
}

// thay từng byte của word4 bằng giá trị tương ứng trong sBox, ví dụ với S_BOX thì [0x01, 0x02, 0x03, 0x04] thành [0x7c, 0x77, 0x7b, 0xf2]
// mục đích tạo non-linearity (phi tuyến) trong quá trình mở rộng khóa để tăng cường bảo mật, giúp chống lại các cuộc tấn công phân tích mật mã như linear và differential cryptanalysis
function subWord(word4, sBox) {
  return new Uint8Array([
    sBox[word4[0]],
    sBox[word4[1]],
    sBox[word4[2]],
    sBox[word4[3]],
  ]);
}

// thêm padding PKCS#7 vào data để độ dài là bội số của blockSize (mặc định 16 byte), ví dụ với blockSize 16 thì "YELLOW SUBMARINE" (16 byte) sẽ được thêm một block mới chứa 16 byte giá trị 0x10, còn "YELLOW SUBMARIN" (15 byte) sẽ được thêm 1 byte giá trị 0x01
function pkcs7Pad(data, blockSize = 16) {
  const remainder = data.length % blockSize; // xem thiếu bao nhiêu byte để đủ blockSize
  const padLen = remainder === 0 ? blockSize : blockSize - remainder; // đủ thì thêm một block mới, thiếu thì thêm phần thiếu
  // giá trị byte padding là padLen ví dụ thiếu 15 bypte thì thêm 0x0f, thiếu 1 byte thì thêm 0x01, đủ blockSize thì thêm 0x10
  const out = new Uint8Array(data.length + padLen);
  out.set(data, 0); // copy data gốc vào đầu mảng mới
  out.fill(padLen, data.length); // điền giá trị padding vào phần còn lại của mảng
  return out;
}

function pkcs7Unpad(data, blockSize = 16) {
  if (data.length === 0 || data.length % blockSize !== 0) {
    throw new Error("Invalid PKCS#7 padded data length");
  }
  const padLen = data[data.length - 1]; // giá trị byte cuối cùng cho biết độ dài của padding
  if (padLen < 1 || padLen > blockSize)
    throw new Error("Invalid PKCS#7 padding");
  for (let i = data.length - padLen; i < data.length; i++) {
    if (data[i] !== padLen) throw new Error("Invalid PKCS#7 padding"); // duyệt phần padding để kiểm tra tất cả byte padding đều có giá trị bằng padLen, nếu không thì padding không hợp lệ
  }
  return data.slice(0, data.length - padLen); // cắt bỏ phần padding để trả về data gốc
}

// nhân a với b trong trường GF(2^8) với đa thức bất khả quy m(x) = x^8 + x^4 + x^3 + x + 1 (0x11b)
function gfMultiply(a, b) {
  let p = 0;
  let aa = a & 0xff; // lấy đúng 1 byte của a, đảm bảo không bị tràn khi shift trái và XOR với 0x1b
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

// tạo một mảng byte ngẫu nhiên có độ dài nhất định, ví dụ randomBytes(4) sẽ trả về Uint8Array gồm 4 byte ngẫu nhiên như [0x3f, 0xa7, 0x1c, 0x9d]
function randomBytes(length) {
  if (!Number.isInteger(length) || length <= 0) {
    throw new Error("randomBytes length must be a positive integer");
  }
  const out = new Uint8Array(length);
  // NOTE: Uses Math.random, which is not cryptographically secure.
  // This is kept to honor the constraint of not using the Node.js
  // crypto module while still avoiding deterministic IVs.
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
