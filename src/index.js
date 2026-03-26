"use strict";

const fs = require("fs");
const path = require("path");
const { AES128 } = require("./aes");
const { measure } = require("./benchmark");
const { pkcs7Pad, xorBytes, randomBytes } = require("./utils");

function ensureSampleInput(filePath) {
  if (!fs.existsSync(filePath)) {
    const sample =
      "AES-128 manual implementation test file.\nThis file will be encrypted and decrypted.\n";
    fs.writeFileSync(filePath, sample, "utf8");
  }
}

async function processSingleFile(aes, inputPath, outputRoot) {
  const outputDir = path.resolve(outputRoot);
  const baseName = path.basename(inputPath, path.extname(inputPath));
  const perFileOutputDir = path.join(outputDir, baseName);
  fs.mkdirSync(perFileOutputDir, { recursive: true });

  const encryptedPath = path.join(perFileOutputDir, "encrypted.bin");
  const decryptedPath = path.join(perFileOutputDir, "decrypted.txt");

  const original = fs.readFileSync(inputPath);
  console.log(`Original size (bytes): ${original.length}`);

  const padded = pkcs7Pad(Uint8Array.from(original), 16);
  const ivForBenchmark = randomBytes(16);

  const encryptedCore = new Uint8Array(padded.length);
  await measure("Encryption core time (CBC excl. IV/padding)", () => {
    let previous = ivForBenchmark;
    for (let offset = 0; offset < padded.length; offset += 16) {
      const block = padded.subarray(offset, offset + 16);
      const xored = xorBytes(block, previous);
      const encrypted = aes.encryptBlock(xored);
      encryptedCore.set(encrypted, offset);
      previous = encrypted;
    }
    return encryptedCore;
  });

  const decryptedCore = new Uint8Array(padded.length);
  await measure("Decryption core time (CBC excl. IV/unpadding)", () => {
    let previous = ivForBenchmark;
    for (let offset = 0; offset < encryptedCore.length; offset += 16) {
      const block = encryptedCore.subarray(offset, offset + 16);
      const decrypted = aes.decryptBlock(block);
      const plainBlock = xorBytes(decrypted, previous);
      decryptedCore.set(plainBlock, offset);
      previous = block;
    }
    return decryptedCore;
  });

  const encryptedBytes = aes.encryptBytes(original);
  console.log(`Encrypted size (bytes in memory): ${encryptedBytes.length}`);
  const decryptedBytes = aes.decryptBytes(encryptedBytes);

  fs.writeFileSync(encryptedPath, Buffer.from(encryptedBytes));
  const encryptedOnDisk = fs.statSync(encryptedPath).size;
  console.log(`Encrypted size (bytes on disk): ${encryptedOnDisk}`);
  console.log(
    `Delta (encrypted on disk - original): ${encryptedOnDisk - original.length}`,
  );
  fs.writeFileSync(decryptedPath, Buffer.from(decryptedBytes));

  const recovered = Buffer.from(decryptedBytes);
  const match = Buffer.from(original).equals(Buffer.from(recovered));

  console.log("----");
  console.log(`Input file: ${inputPath}`);
  console.log(`Encrypted file: ${encryptedPath}`);
  console.log(`Decrypted file: ${decryptedPath}`);
  console.log(`Integrity check: ${match ? "PASS" : "FAIL"}`);

  return match;
}

async function processDirectory(inputDir, outputRoot, key) {
  const aes = new AES128(key);
  const entries = fs.readdirSync(inputDir, { withFileTypes: true });
  let allOk = true;

  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const inputPath = path.join(inputDir, entry.name);
    const ok = await processSingleFile(aes, inputPath, outputRoot);
    if (!ok) allOk = false;
  }

  if (!allOk) {
    process.exitCode = 1;
  }
}

async function main() {
  const target = process.argv[2]
    ? path.resolve(process.argv[2])
    : path.resolve(process.cwd(), "input");

  const key = process.argv[3] || "000102030405060708090a0b0c0d0e0f";
  const outputDir = path.resolve(process.cwd(), "output");

  if (!fs.existsSync(target)) {
    const parent = path.dirname(target);
    const name = path.basename(target);
    if (fs.existsSync(parent) && name !== "input") {
      ensureSampleInput(target);
    } else {
      throw new Error(
        `Input path not found: ${target}. Hãy tạo thư mục 'input' và đặt file vào đó hoặc chỉ định đường dẫn file/tệp.`,
      );
    }
  }

  const stat = fs.statSync(target);
  if (stat.isDirectory()) {
    console.log(`Processing all files in directory: ${target}`);
    await processDirectory(target, outputDir, key);
  } else {
    const aes = new AES128(key);
    const ok = await processSingleFile(aes, target, outputDir);
    if (!ok) {
      process.exitCode = 1;
    }
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error("Error:", error.message);
    process.exitCode = 1;
  });
}

module.exports = { main };
