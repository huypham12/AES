"use strict";

const fs = require("fs");
const path = require("path");
const readline = require("readline");
const { AES } = require("./aes");
const { measure } = require("./benchmark");
const {
  pkcs7Pad,
  xorBytes,
  randomBytes,
  toBytes,
  hexToBytes,
} = require("./utils");

async function processSingleFile(aes, inputPath, outputRoot) {
  const outputDir = path.resolve(outputRoot); // đảm bảo outputRoot là đường dẫn tuyệt đối
  const baseName = path.basename(inputPath, path.extname(inputPath)); // lấy tên file không có phần mở rộng để đặt tên thư mục con trong output
  const perFileOutputDir = path.join(outputDir, baseName); // mỗi file sẽ có một thư mục riêng trong output để chứa encrypted.bin và decrypted.txt
  fs.mkdirSync(perFileOutputDir, { recursive: true }); // tạo thư mục nếu chưa tồn tại, nếu đã tồn tại thì không làm gì (tránh lỗi nếu chạy lại nhiều lần)

  const encryptedPath = path.join(perFileOutputDir, "encrypted.bin"); // lưu file đã được mã hóa ở đây
  const decryptedPath = path.join(perFileOutputDir, "decrypted.txt"); // lưu file đã được giải mã ở đây

  const original = fs.readFileSync(inputPath); // đọc file gốc vào bộ nhớ để benchmark và kiểm tra tính toàn vẹn sau khi giải mã
  console.log(`Kích thước gốc (byte): ${original.length}`); // kích thước file gốc để so sánh với kích thước file đã mã hóa trên đĩa sau này

  // CBC algorithm core timing only:
  // - Excludes IV generation
  // - Excludes PKCS#7 padding/unpadding
  // The actual encrypt/decrypt for output is still performed via AES128 methods.
  const padded = pkcs7Pad(Uint8Array.from(original), 16); // bù byte nếu thiếu, đủ thì cũng thêm một block mới, vì padding luôn nhìn byte cuối để xem đã padding bao nhiêu byte, ví dụ padding 3 byte thì sẽ thêm 0x03 0x03 0x03, nếu lỡ vừa đủ blocksize mà không thêm block mới thì khi giải mã có thể bị nhầm thành số byte padding, lúc đó sẽ sai
  const ivForBenchmark = randomBytes(16);

  const encryptedCore = new Uint8Array(padded.length);
  await measure("Thời gian mã hóa:", () => {
    let previous = ivForBenchmark;
    for (let offset = 0; offset < padded.length; offset += 16) {
      const block = padded.subarray(offset, offset + 16);
      // C[i] = AES( P[i] XOR C[i-1] )
      // C[0] = AES( P[0] XOR IV )
      const xored = xorBytes(block, previous);
      const encrypted = aes.encryptBlock(xored);
      encryptedCore.set(encrypted, offset); // ghi vào encryptedCore tại vị trí tương ứng
      previous = encrypted;
    }
    return encryptedCore;
  });

  const decryptedCore = new Uint8Array(padded.length);
  await measure("Thời gian giải mã:", () => {
    let previous = ivForBenchmark;
    for (let offset = 0; offset < encryptedCore.length; offset += 16) {
      const block = encryptedCore.subarray(offset, offset + 16);
      // P[i] = AES⁻¹(C[i]) XOR C[i-1] giải mã xor với block trước đó
      const decrypted = aes.decryptBlock(block);
      const plainBlock = xorBytes(decrypted, previous); //
      decryptedCore.set(plainBlock, offset); // ghi vào decryptedCore tại vị trí tương ứng
      previous = block;
    }
    return decryptedCore;
  });

  const encryptedBytes = aes.encryptBytes(original);
  console.log(`Kích thước sau mã hóa: ${encryptedBytes.length}`);
  const decryptedBytes = aes.decryptBytes(encryptedBytes);

  fs.writeFileSync(encryptedPath, Buffer.from(encryptedBytes)); // lưu file đã mã hóa ra đĩa, dùng Buffer.from để đảm bảo ghi đúng byte, nếu dùng trực tiếp Uint8Array có thể bị lỗi encoding
  const encryptedOnDisk = fs.statSync(encryptedPath).size; // kích thước file đã mã hóa trên đĩa, có thể khác với kích thước trong bộ nhớ do hệ thống file có thể lưu theo block, hoặc do metadata, hoặc do encoding nếu không dùng Buffer đúng cách
  console.log(
    `Chênh lệch kích thước (file mã hóa và file gốc): ${encryptedOnDisk - original.length}`,
  ); // chênh lệch giữa kích thước file đã mã hóa trên đĩa và kích thước file gốc, thường là delta lớn hơn 0 do padding
  fs.writeFileSync(decryptedPath, Buffer.from(decryptedBytes)); // lưu file đã giải mã ra đĩa, dùng Buffer.from để đảm bảo ghi đúng byte, nếu dùng trực tiếp Uint8Array có thể bị lỗi encoding

  const recovered = Buffer.from(decryptedBytes); // chuyển decryptedBytes thành Buffer để so sánh với original (cũng là Buffer), vì Buffer có method equals để so sánh nội dung, còn Uint8Array thì không có, nếu so sánh trực tiếp giữa Uint8Array và Buffer sẽ không đúng vì chúng là hai kiểu khác nhau
  const match = Buffer.from(original).equals(Buffer.from(recovered)); // so sánh nội dung của original và recovered, nếu giống nhau thì giải mã thành công, nếu khác nhau thì có lỗi trong quá trình mã hóa hoặc giải mã

  console.log("----");
  console.log(`Tệp đầu vào: ${inputPath}`);
  console.log(`Tệp đã mã hóa: ${encryptedPath}`);
  console.log(`Tệp đã giải mã: ${decryptedPath}`);
  console.log(`Kiểm tra toàn vẹn: ${match ? "ĐẠT" : "KHÔNG ĐẠT"}\n`);
  console.log("============================================");

  return match;
}

async function processDirectory(inputDir, outputRoot, key) {
  const aes = new AES(key);
  const entries = fs.readdirSync(inputDir, { withFileTypes: true }); // đọc tất cả entry trong thư mục, với withFileTypes: true thì sẽ trả về Dirent objects có thông tin về loại entry (file hay thư mục)
  let allOk = true; // biến để theo dõi xem tất cả file có giải mã đúng hay không, nếu có bất kỳ file nào giải mã sai thì sẽ đặt allOk thành false

  // duyệt qua tất cả entry, nếu là file thì xử lý, nếu là thư mục thì bỏ qua (không xử lý đệ quy)
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

function askQuestion(rl, query, options = { trim: true }) {
  return new Promise((resolve) =>
    rl.question(query, (ans) => {
      if (options && options.trim === false) {
        // Preserve leading/trailing spaces; only drop trailing CR/LF defensively.
        resolve(ans.replace(/[\r\n]+$/g, ""));
        return;
      }
      resolve(ans.trim());
    }),
  );
}

async function askChoice(rl, { prompt, validChoices, invalidMessage }) {
  while (true) {
    // Normalize menu input only (allow " 1 ").
    const raw = await askQuestion(rl, prompt, { trim: false });
    const answer = raw.trim();
    if (validChoices.includes(answer)) return answer;
    console.error(invalidMessage);
  }
}

function getDefaultHexKey(keySize) {
  if (keySize === 128) return "000102030405060708090a0b0c0d0e0f";
  if (keySize === 192)
    return "000102030405060708090a0b0c0d0e0f1011121314151617";
  return "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
}

function parseKeyByMode(rawKey, mode, expectedBytes) {
  if (mode === "hex") {
    const clean = rawKey.replace(/\s+/g, "");
    if (!/^[0-9a-fA-F]+$/.test(clean)) {
      throw new Error("Hex key chỉ được chứa ký tự [0-9a-fA-F]");
    }
    const expectedHexLen = expectedBytes * 2;
    if (clean.length !== expectedHexLen) {
      throw new Error(
        `Hex key cho AES-${expectedBytes * 8} phải có đúng ${expectedHexLen} ký tự`,
      );
    }
    return hexToBytes(clean);
  }

  const textBytes = toBytes(rawKey);
  if (textBytes.length !== expectedBytes) {
    throw new Error(
      `Text key có ${textBytes.length} bytes, cần đúng ${expectedBytes} bytes cho AES-${expectedBytes * 8}`,
    );
  }
  return textBytes;
}

async function main() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  let cancelled = false;
  const cancel = () => {
    if (cancelled) return;
    cancelled = true;
    console.log("\nCancelled by user");
    rl.close();
    process.exit(1);
  };

  // Handle Ctrl+C consistently.
  rl.on("SIGINT", cancel);
  process.once("SIGINT", cancel);

  try {
    // Nếu không truyền gì, mặc định xử lý tất cả file trong thư mục "input".
    const target = process.argv[2]
      ? path.resolve(process.argv[2])
      : path.resolve(process.cwd(), "input");

    const outputDir = path.resolve(process.cwd(), "output");

    if (!fs.existsSync(target)) {
      throw new Error(
        `Input path not found: ${target}. Hãy tạo thư mục 'input' và đặt file vào đó hoặc chỉ định đường dẫn file/tệp.`,
      );
    }

    console.log("Choose key size:");
    console.log("1. AES-128");
    console.log("2. AES-192");
    console.log("3. AES-256");

    const sizeChoice = await askChoice(rl, {
      prompt: "> ",
      validChoices: ["1", "2", "3"],
      invalidMessage: "Invalid choice, please try again (choose 1, 2, or 3).",
    });
    const keySize = sizeChoice === "2" ? 192 : sizeChoice === "3" ? 256 : 128;

    const expectedBytes = keySize / 8;
    console.log(`\nYou selected: AES-${keySize} (${expectedBytes} bytes key).`);
    console.log("Choose key format:");
    console.log("1. Hex");
    console.log("2. Text (UTF-8)");
    const formatChoice = await askChoice(rl, {
      prompt: "> ",
      validChoices: ["1", "2"],
      invalidMessage: "Invalid choice, please try again (choose 1 or 2).",
    });
    const keyFormat = formatChoice === "2" ? "text" : "hex";
    console.log(`Enter your key (${keyFormat}).`);
    console.log("Press Enter (empty) to use default key.");
    console.log("Spaces are considered part of the key.");

    let keyBytes;
    while (true) {
      // Preserve leading/trailing spaces for keys; do not trim.
      const userKey = await askQuestion(rl, "Key: ", { trim: false });
      if (!userKey) {
        const defaultHexKey = getDefaultHexKey(keySize);
        keyBytes = hexToBytes(defaultHexKey);
        console.log(`Using default key (hex): ${defaultHexKey}`);
        break;
      }

      try {
        keyBytes = parseKeyByMode(userKey, keyFormat, expectedBytes);
        break;
      } catch (error) {
        console.error(`\n[Lỗi] ${error.message}`);
      }
    }

    const stat = fs.statSync(target);
    if (stat.isDirectory()) {
      console.log(`Đang xử lý tất cả tệp trong thư mục: ${target}`);
      await processDirectory(target, outputDir, keyBytes);
    } else {
      const aes = new AES(keyBytes);
      const ok = await processSingleFile(aes, target, outputDir);
      if (!ok) {
        process.exitCode = 1;
      }
    }
  } finally {
    rl.close();
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error("Lỗi:", error.message);
    process.exitCode = 1;
  });
}

module.exports = { main };
