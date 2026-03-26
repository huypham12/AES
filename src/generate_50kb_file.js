"use strict";

const fs = require("fs");
const path = require("path");

// ====== Config ======
const DEFAULT_UNIT = 1024; // KB
const LINE = "AES-128 manual implementation test file.\n";

// /input nằm cùng cấp với /src
const INPUT_DIR = path.join(__dirname, "..", "input");

// ====== Utils ======
function parseArgs() {
  const fileName = process.argv[2];
  const sizeArg = process.argv[3];

  if (!fileName || !sizeArg) {
    throw new Error(
      "Cách dùng: node script.js <ten_file> <size_kb>\nVí dụ: node script.js file1.txt 10",
    );
  }

  const sizeKB = Number(sizeArg);

  if (isNaN(sizeKB) || sizeKB <= 0) {
    throw new Error("Kích thước không hợp lệ. Phải là số dương (KB).");
  }

  return {
    fileName,
    targetSize: sizeKB * DEFAULT_UNIT,
  };
}

function ensureInputDir() {
  if (!fs.existsSync(INPUT_DIR)) {
    fs.mkdirSync(INPUT_DIR, { recursive: true });
  }
}

function generateContent(targetSize, line) {
  const lineSize = Buffer.byteLength(line, "utf8");
  let content = "";

  while (Buffer.byteLength(content, "utf8") + lineSize <= targetSize) {
    content += line;
  }

  return content;
}

function writeFile(fileName, content) {
  const filePath = path.join(INPUT_DIR, fileName);
  fs.writeFileSync(filePath, content, "utf8");
  return filePath;
}

function logFileSize(filePath) {
  const stats = fs.statSync(filePath);
  console.log(
    `File "${path.basename(filePath)}": ${stats.size} bytes (~${(
      stats.size / 1024
    ).toFixed(2)} KB)`,
  );
}

// ====== Main ======
function main() {
  try {
    const { fileName, targetSize } = parseArgs();

    ensureInputDir();

    const content = generateContent(targetSize, LINE);

    const filePath = writeFile(fileName, content);

    logFileSize(filePath);
  } catch (err) {
    console.error("Lỗi:", err.message);
    process.exit(1);
  }
}

main();
