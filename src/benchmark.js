"use strict";

function measure(label, fn) {
  const start = process.hrtime.bigint();
  const result = fn();
  const isPromise =
    result && typeof result === "object" && typeof result.then === "function";

  if (isPromise) {
    return result.then((value) => {
      const end = process.hrtime.bigint();
      const ms = Number(end - start) / 1e6;
      console.log(`${label}: ${ms.toFixed(3)} ms`);
      return { result: value, ms };
    });
  }

  const end = process.hrtime.bigint();
  const ms = Number(end - start) / 1e6;
  console.log(`${label}: ${ms.toFixed(3)} ms`);
  return { result, ms };
}

module.exports = { measure };
