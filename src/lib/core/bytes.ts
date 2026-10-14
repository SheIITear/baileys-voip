/**
 * ============================================================================
 * CROSS-CUTTING — Byte/encoding utilities
 * ============================================================================
 *
 * Safe hex/base64/UTF-8 conversion, concatenation, timing-safe comparison and
 * big-endian read/write helpers used across RTP/SRTP/STUN parsing and key
 * material handling. One audited set of byte primitives avoids subtle off-by-
 * one and encoding bugs that would break crypto.
 */

import { timingSafeEqual } from "node:crypto";

/**
 * Encode a UTF-8 string to a byte array.
 * Used for HKDF info labels, LID strings, and XMPP signaling fields.
 */
export const utf8ToBytes = (value: string): Uint8Array =>
  new Uint8Array(Buffer.from(value, "utf8"));

/**
 * Decode a byte array as UTF-8.
 * Used to extract human-readable labels from wire-format key material.
 */
export const bytesToUtf8 = (value: Uint8Array): string =>
  Buffer.from(value).toString("utf8");

/**
 * Encode bytes as uppercase hex. Used for logging/diagnostics and for
 * building hex payloads in XMPP stanzas.
 */
export const bytesToHex = (value: Uint8Array): string =>
  Buffer.from(value).toString("hex").toUpperCase();

/**
 * Decode a hex string to bytes. Strips separators (spaces, colons, dashes).
 * Throws on odd-length input.
 */
export const hexToBytes = (value: string): Uint8Array => {
  const cleaned = value.replace(/[:\-\s]/g, "").trim();
  if (!cleaned) return new Uint8Array(0);
  if (cleaned.length % 2 !== 0) throw new Error("hex input must have even length");
  return new Uint8Array(Buffer.from(cleaned, "hex"));
};

/**
 * Encode bytes as standard base64. Used for relay tokens and key material
 * that the WhatsApp relay server expects.
 */
export const encodeBase64Bytes = (value: Uint8Array): string =>
  Buffer.from(value).toString("base64");

/**
 * Decode a base64 string to bytes. Falls back to UTF-8 encoding on failure
 * because some WhatsApp XMPP payloads carry text where base64 is expected.
 */
export const decodeBase64Bytes = (value: string): Uint8Array => {
  const trimmed = value.trim();
  if (!trimmed) return new Uint8Array(0);
  try { return new Uint8Array(Buffer.from(trimmed, "base64")); }
  catch { return utf8ToBytes(trimmed); }
};

/** Create a shallow copy of a byte array (new buffer, same data). */
export const cloneBytes = (value: Uint8Array): Uint8Array =>
  new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));

/** Concatenate multiple byte arrays into one. Used extensively by packet builders. */
export const concatBytes = (...parts: Uint8Array[]): Uint8Array => {
  const totalLength = parts.reduce((sum, part) => sum + part.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.length; }
  return result;
};

/** Create a merged copy from an array of byte arrays. */
export const mergeBytes = (parts: Uint8Array[]): Uint8Array => concatBytes(...parts);

/**
 * Timing-safe byte comparison. Prevents side-channel timing attacks when
 * comparing SRTP auth tags, WARP MI tags, and other MACs.
 */
export const equalBytes = (left: Uint8Array, right: Uint8Array): boolean => {
  if (left.length !== right.length) return false;
  return timingSafeEqual(Buffer.from(left), Buffer.from(right));
};

/** Assert exact byte array length, throwing a descriptive error on mismatch. */
export const ensureLength = (value: Uint8Array, expected: number, label: string): void => {
  if (value.length !== expected) throw new Error(`${label} must be ${expected} bytes, got ${value.length}`);
};

/** Read a 16-bit big-endian unsigned integer from a byte array. Used for RTP seq numbers and STUN attribute lengths. */
export const readUint16BE = (value: Uint8Array, offset: number): number =>
  (value[offset]! << 8) | value[offset + 1]!;

/** Read a 32-bit big-endian unsigned integer. Used for SSRCs, RTP timestamps, STUN magic cookie. */
export const readUint32BE = (value: Uint8Array, offset: number): number =>
  ((value[offset]! << 24) >>> 0) | (value[offset + 1]! << 16) | (value[offset + 2]! << 8) | value[offset + 3]!;

/** Write a 16-bit big-endian integer at an offset. */
export const writeUint16BE = (target: Uint8Array, offset: number, value: number): void => {
  target[offset] = (value >>> 8) & 0xff;
  target[offset + 1] = value & 0xff;
};

/** Write a 32-bit big-endian integer at an offset. */
export const writeUint32BE = (target: Uint8Array, offset: number, value: number): void => {
  target[offset] = (value >>> 24) & 0xff;
  target[offset + 1] = (value >>> 16) & 0xff;
  target[offset + 2] = (value >>> 8) & 0xff;
  target[offset + 3] = value & 0xff;
};

/** Convert a 32-bit number to a 4-byte big-endian array. Used for SSRC fields. */
export const uint32ToBytes = (value: number): Uint8Array => {
  const result = new Uint8Array(4);
  writeUint32BE(result, 0, value >>> 0);
  return result;
};

/** Convert a BigInt to a 6-byte big-endian array. Used for SRTP packet index. */
export const uint48ToBytes = (value: bigint): Uint8Array => {
  const result = new Uint8Array(6);
  for (let index = 0; index < 6; index += 1) {
    result[index] = Number((value >> BigInt((5 - index) * 8)) & 0xffn);
  }
  return result;
};

/** Convert a BigInt to an 8-byte big-endian array. Used for SFrame counters and CONNECTION-ID. */
export const uint64ToBytes = (value: bigint): Uint8Array => {
  const result = new Uint8Array(8);
  for (let index = 0; index < 8; index += 1) {
    result[index] = Number((value >> BigInt((7 - index) * 8)) & 0xffn);
  }
  return result;
};

/** Read a 64-bit big-endian unsigned integer as BigInt. */
export const readUint64BE = (value: Uint8Array, offset: number): bigint => {
  let result = 0n;
  for (let index = 0; index < 8; index += 1) {
    result = (result << 8n) | BigInt(value[offset + index]!);
  }
  return result;
};

/** Shorthand for reading a 32-bit BE unsigned int from a byte array. */
export const bytesToUint32 = (value: Uint8Array, offset = 0): number =>
  readUint32BE(value, offset);
