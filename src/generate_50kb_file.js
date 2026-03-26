const fs = require("fs");

const targetSize = 50 * 1024; // ~50KB
const line = "AES-128 manual implementation test file.\n";

let content = "";

// Chỉ thêm dòng nếu vẫn còn đủ chỗ cho nguyên 1 dòng
while (
  Buffer.byteLength(content, "utf8") + Buffer.byteLength(line, "utf8") <=
  targetSize
) {
  content += line;
}

// Ghi file
fs.writeFileSync("file1.txt", content, "utf8");

// Kiểm tra size
const stats = fs.statSync("file1.txt");
console.log("File size:", stats.size, "bytes");
