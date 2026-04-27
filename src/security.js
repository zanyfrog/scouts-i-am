"use strict";

const crypto = require("node:crypto");

const HASH_ITERATIONS = 210000;
const HASH_KEY_LENGTH = 64;
const HASH_DIGEST = "sha512";
const TOTP_WINDOW_SECONDS = 30;

function createId(prefix) {
  return `${prefix}_${crypto.randomBytes(8).toString("hex")}`;
}

function createToken() {
  return crypto.randomBytes(24).toString("hex");
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const passwordHash = crypto.pbkdf2Sync(
    password,
    salt,
    HASH_ITERATIONS,
    HASH_KEY_LENGTH,
    HASH_DIGEST
  ).toString("hex");

  return { passwordHash, salt };
}

function verifyPassword(password, passwordHash, salt) {
  const candidate = hashPassword(password, salt);
  return crypto.timingSafeEqual(
    Buffer.from(candidate.passwordHash, "hex"),
    Buffer.from(passwordHash, "hex")
  );
}

function createTotpSecret() {
  return crypto.randomBytes(20).toString("hex");
}

function generateTotp(secret, at = Date.now()) {
  const counter = Math.floor(at / 1000 / TOTP_WINDOW_SECONDS);
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = crypto
    .createHmac("sha1", Buffer.from(secret, "hex"))
    .update(message)
    .digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);

  return String(binary % 1000000).padStart(6, "0");
}

function verifyTotp(secret, code, at = Date.now()) {
  for (let offset = -1; offset <= 1; offset += 1) {
    const windowTime = at + offset * TOTP_WINDOW_SECONDS * 1000;
    if (generateTotp(secret, windowTime) === code) {
      return true;
    }
  }

  return false;
}

module.exports = {
  createId,
  createToken,
  createTotpSecret,
  generateTotp,
  hashPassword,
  verifyPassword,
  verifyTotp
};
