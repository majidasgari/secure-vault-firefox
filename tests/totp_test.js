/*
 * TOTP tests: the RFC 6238 vectors, `otpauth://` parsing, and the "what is this stored value"
 * decision. Plain Node, no dependencies:  node tests/totp_test.js
 */
"use strict";

const totp = require("../extension/lib/totp.js");

let failures = 0;
let checks = 0;

function check(name, condition, detail) {
  checks += 1;
  if (condition) {
    console.log("  ok   " + name);
  } else {
    failures += 1;
    console.log("  FAIL " + name + (detail === undefined ? "" : "  -> " + JSON.stringify(detail)));
  }
}

function equal(name, actual, expected) {
  check(name, actual === expected, { actual: actual, expected: expected });
}

function bytesToString(bytes) {
  return Array.from(bytes)
    .map((value) => String.fromCharCode(value))
    .join("");
}

async function main() {
  console.log("base32");
  equal(
    "decodes the RFC 6238 key to its ASCII seed",
    bytesToString(totp.base32Decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")),
    "12345678901234567890"
  );
  equal("tolerates padding and spaces", bytesToString(totp.base32Decode("gezd gnbvgy3tqojq gezd gnbvgy3tqojq====")), "12345678901234567890");
  let threw = false;
  try {
    totp.base32Decode("0189!");
  } catch (error) {
    threw = true;
  }
  check("rejects a non-base32 character", threw);

  console.log("RFC 6238 vectors (SHA-1, seed 12345678901234567890)");
  const seed = { secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", algorithm: "SHA1", period: 30 };
  const vectors = [
    [59, "94287082", "287082"],
    [1111111109, "07081804", "081804"],
    [1111111111, "14050471", "050471"],
    [1234567890, "89005924", "005924"],
    [2000000000, "69279037", "279037"],
    [20000000000, "65353130", "353130"]
  ];
  for (const [at, eight, six] of vectors) {
    const long = await totp.generateFromDescriptor(Object.assign({ digits: 8 }, seed), at);
    equal(`T=${at} → 8 digits`, long.code, eight);
    const short = await totp.generateFromDescriptor(Object.assign({ digits: 6 }, seed), at);
    equal(`T=${at} → 6 digits`, short.code, six);
  }
  const windowed = await totp.generateFromDescriptor(Object.assign({ digits: 6 }, seed), 59.9);
  equal("a fractional timestamp stays in the same step", windowed.code, "287082");

  console.log("otpauth://");
  const parsed = totp.parseOtpauth(
    "otpauth://totp/GitHub:max%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=8&period=60&algorithm=SHA256"
  );
  equal("secret", parsed.secret, "JBSWY3DPEHPK3PXP");
  equal("issuer", parsed.issuer, "GitHub");
  equal("label is decoded", parsed.label, "GitHub:max@example.com");
  equal("digits", parsed.digits, 8);
  equal("period", parsed.period, 60);
  equal("algorithm", parsed.algorithm, "SHA256");
  equal("a non-totp URI is not a descriptor", totp.parseOtpauth("otpauth://hotp/x?secret=AA"), null);
  equal("a plain secret is not a URI", totp.parseOtpauth("JBSWY3DPEHPK3PXP"), null);

  console.log("valueToCode");
  const uri = await totp.valueToCode("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59);
  equal("otpauth URI is live", uri.live, true);
  equal("otpauth URI code", uri.code, "287082");
  const bare = await totp.valueToCode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59);
  equal("bare base32 secret is live", bare.live, true);
  equal("bare base32 code", bare.code, "287082");
  const pasted = await totp.valueToCode("654321", 59);
  equal("a pasted code is not live", pasted.live, false);
  equal("a pasted code is returned as-is", pasted.code, "654321");
  equal("an empty placeholder is nothing", await totp.valueToCode("—"), null);
  equal("prose is nothing", await totp.valueToCode("recovery codes in the note below"), null);
  equal("a sentence in capitals is not a secret", totp.looksLikeSecret("RECOVERY CODES HERE"), false);
  equal("six letters are not a secret", totp.looksLikeSecret("ABCDEF"), false);
  equal("a 16-char secret is a secret", totp.looksLikeSecret("JBSWY3DPEHPK3PXP"), true);

  console.log("");
  console.log(`${checks - failures}/${checks} checks passed`);
  return failures ? 1 : 0;
}

main().then(
  (code) => process.exit(code),
  (error) => {
    console.error(error);
    process.exit(2);
  }
);
