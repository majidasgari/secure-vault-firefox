/*
 * TOTP for the credential entries that store an `otpauth://` URI.
 *
 * The migration keeps a KeePass OTP field verbatim, so an entry's OTP value is either an
 * `otpauth://totp/...?secret=...` URI (the common case for KeePassXC's TOTP column) or a plain
 * code someone pasted (a backup/static code). This module turns the first into a live 6-digit
 * code with WebCrypto's HMAC-SHA1 and returns the second unchanged — it never invents a code
 * for a value it does not understand.
 *
 * No network, no randomness, no storage: the secret is used for one HMAC and dropped.
 */
(function (global) {
  "use strict";

  const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

  /** Decode an RFC 4648 base32 string (padding and spaces tolerated). */
  function base32Decode(input) {
    const clean = String(input || "").toUpperCase().replace(/=+$/, "").replace(/[\s-]/g, "");
    if (!clean) return new Uint8Array(0);
    let bits = 0;
    let value = 0;
    const out = [];
    for (const character of clean) {
      const index = BASE32_ALPHABET.indexOf(character);
      if (index < 0) throw new Error("invalid_base32");
      value = (value << 5) | index;
      bits += 5;
      if (bits >= 8) {
        out.push((value >>> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }
    return new Uint8Array(out);
  }

  /** Parse an `otpauth://` URI into its TOTP parameters (null when it is not one). */
  function parseOtpauth(uri) {
    const text = String(uri || "").trim();
    if (!/^otpauth:\/\//i.test(text)) return null;
    let url;
    try {
      url = new URL(text.replace(/^otpauth:\/\//i, "https://"));
    } catch (error) {
      return null;
    }
    if (String(url.host || "").toLowerCase() !== "totp") return null;
    const secret = url.searchParams.get("secret");
    if (!secret) return null;
    const algorithm = String(url.searchParams.get("algorithm") || "SHA1").toUpperCase();
    const digits = Number(url.searchParams.get("digits") || 6) || 6;
    const period = Number(url.searchParams.get("period") || 30) || 30;
    const label = decodeURIComponent((url.pathname || "").replace(/^\/+/, ""));
    return {
      secret: secret,
      algorithm: algorithm,
      digits: Math.min(10, Math.max(4, digits)),
      period: Math.max(5, period),
      issuer: url.searchParams.get("issuer") || "",
      label: label
    };
  }

  /** Big-endian 8-byte counter for the given time step. */
  function counterBytes(counter) {
    const buffer = new Uint8Array(8);
    let value = Math.floor(counter);
    for (let index = 7; index >= 0; index -= 1) {
      buffer[index] = value & 0xff;
      value = Math.floor(value / 256);
    }
    return buffer;
  }

  /** Generate the code for a parsed TOTP descriptor at time `atSeconds`. */
  async function generateFromDescriptor(descriptor, atSeconds) {
    const key = base32Decode(descriptor.secret);
    if (!key.length) throw new Error("empty_secret");
    const now = typeof atSeconds === "number" ? atSeconds : Date.now() / 1000;
    const step = Math.floor(now / descriptor.period);
    const cryptoApi = global.crypto || (typeof require === "function" ? require("crypto").webcrypto : null);
    const hmacKey = await cryptoApi.subtle.importKey(
      "raw",
      key,
      { name: "HMAC", hash: { name: descriptor.algorithm === "SHA256" ? "SHA-256" : descriptor.algorithm === "SHA512" ? "SHA-512" : "SHA-1" } },
      false,
      ["sign"]
    );
    const signature = new Uint8Array(
      await cryptoApi.subtle.sign("HMAC", hmacKey, counterBytes(step))
    );
    const offset = signature[signature.length - 1] & 0x0f;
    const binary =
      ((signature[offset] & 0x7f) << 24) |
      ((signature[offset + 1] & 0xff) << 16) |
      ((signature[offset + 2] & 0xff) << 8) |
      (signature[offset + 3] & 0xff);
    const code = String(binary % Math.pow(10, descriptor.digits)).padStart(descriptor.digits, "0");
    const remaining = descriptor.period - (Math.floor(now) % descriptor.period);
    return { code: code, remaining: remaining, period: descriptor.period, digits: descriptor.digits };
  }

  /**
   * A bare base32 secret (what a KeePass "TOTP seed" column often holds).
   *
   * Deliberately strict: the base32 alphabet is ``A–Z`` plus ``2–7``, so a *sentence* in capitals is
   * technically decodable and would silently produce a wrong code. Requiring 16+ characters with
   * no spaces, dashes or punctuation keeps prose out.
   */
  function looksLikeSecret(text) {
    return /^[A-Z2-7]{16,}$/.test(String(text || "").trim().toUpperCase().replace(/=+$/, ""));
  }

  /**
   * Group the digits of a code so it can be read back off the screen.
   *
   * Six digits become two triplets (``287 082``), eight two halves, nine three triplets — the same
   * shape the vault's own viewer shows. This is presentation only: what gets copied or typed is
   * always ``code``, never this string.
   */
  function groupDigits(code) {
    const text = String(code === undefined || code === null ? "" : code);
    if (text.length === 6) return text.slice(0, 3) + " " + text.slice(3);
    if (text.length === 8) return text.slice(0, 4) + " " + text.slice(4);
    if (text.length === 9) return text.slice(0, 3) + " " + text.slice(3, 6) + " " + text.slice(6);
    return text;
  }

  /**
   * Turn a stored OTP value into something to type.
   *
   * @returns {Promise<{code: string, display: string, remaining: number|null, period: number|null,
   *   live: boolean}|null>} `live: true` when the code was generated from an `otpauth://` URI or a
   *   bare base32 secret, `false` when the stored value already *was* a code (a backup code — the
   *   caller decides what to do with it), `null` when the value is not an OTP at all. ``display``
   *   is the grouped form for reading; a code that was not generated is shown exactly as stored.
   */
  async function valueToCode(value, atSeconds) {
    const text = String(value || "").trim();
    if (!text || text === "—") return null;
    const descriptor = parseOtpauth(text);
    if (descriptor) {
      const generated = await generateFromDescriptor(descriptor, atSeconds);
      return {
        code: generated.code,
        display: groupDigits(generated.code),
        remaining: generated.remaining,
        period: descriptor.period,
        live: true
      };
    }
    if (/^\d{4,10}$/.test(text)) {
      return { code: text, display: text, remaining: null, period: null, live: false };
    }
    if (looksLikeSecret(text)) {
      const generated = await generateFromDescriptor(
        { secret: text, algorithm: "SHA1", digits: 6, period: 30 },
        atSeconds
      );
      return {
        code: generated.code,
        display: groupDigits(generated.code),
        remaining: generated.remaining,
        period: 30,
        live: true
      };
    }
    return null;
  }

  const api = {
    base32Decode: base32Decode,
    parseOtpauth: parseOtpauth,
    looksLikeSecret: looksLikeSecret,
    groupDigits: groupDigits,
    generateFromDescriptor: generateFromDescriptor,
    valueToCode: valueToCode
  };

  global.SecureVaultTotp = api;
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})(globalThis);
