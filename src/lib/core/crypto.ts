/**
 * ============================================================================
 * CROSS-CUTTING — Key derivation primitives
 * ============================================================================
 *
 * SHA-256, HMAC-SHA1/256 and HKDF used to derive participant + relay-stream
 * SSRCs, SFrame keys, HBH SRTP keys, and fingerprint HMACs. Label strings and
 * derivation order mirror WhatsApp's native schedules exactly.
 *
 * Why: every crypto layer depends on these matching the official client bit-for-
 * bit. The SSRC determinism, SFrame keying, and HBH salt derivation all depend
 * on exact label strings and HKDF parameter orders.
 */
import { createHash, createHmac } from "node:crypto";
import { bytesToHex, decodeBase64Bytes, hexToBytes, utf8ToBytes } from "./bytes";

/** Labels used as HKDF info strings — must match the native WhatsApp client exactly. */
export const LabelDataChannelCertFingerprintHmac = "data-channel cert fingerprint hmac";
export const LabelE2ESframeKey = "e2e sframe key";
export const LabelHbhSrtpSalt = "hbh srtp salt";
export const LabelHbhSrtpKey = "hbh srtp key";
export const LabelUplinkHbhSrtcpSalt = "uplink hbh srtcp salt";
export const LabelUplinkHbhSrtcpKey = "uplink hbh srtcp key";
export const LabelDownlinkHbhSrtcpSalt = "downlink hbh srtcp salt";
export const LabelDownlinkHbhSrtcpKey = "downlink hbh srtcp key";

export interface RawE2EMaterial {
  rawBytes: Uint8Array;
  baseMaterial: Uint8Array;   // first 32 bytes of raw_e2e
  fingerprintSalt: Uint8Array; // bytes beyond 32 (fingerprint HMAC salt)
}

/** Generic HMAC digest. */
const hmacDigest = (algorithm: "sha1" | "sha256", key: Uint8Array, data: Uint8Array): Uint8Array =>
  new Uint8Array(createHmac(algorithm, key).update(data).digest());

/** SHA-256 hash. Used for SSRC derivation and general fingerprinting. */
export const sha256 = (value: Uint8Array): Uint8Array =>
  new Uint8Array(createHash("sha256").update(value).digest());

export const sha256Hex = (value: Uint8Array): string => bytesToHex(sha256(value));

export const hmacSha1KeyFirst = (key: Uint8Array, data: Uint8Array): Uint8Array =>
  hmacDigest("sha1", key, data);

export const hmacSha256KeyFirst = (key: Uint8Array, data: Uint8Array): Uint8Array =>
  hmacDigest("sha256", key, data);

export const hmacSha1 = (data: Uint8Array, key: Uint8Array): Uint8Array =>
  hmacSha1KeyFirst(key, data);

export const hmacSha256 = (data: Uint8Array, key: Uint8Array): Uint8Array =>
  hmacSha256KeyFirst(key, data);

/**
 * HKDF extract step: HMAC-SHA256(salt, ikm).
 * When salt is all zeros (empty 32-byte block), this is equivalent to
 * passing a 32-byte zero salt per RFC 5869.
 */
export const hkdfExtract = (salt: Uint8Array, ikm: Uint8Array): Uint8Array => {
  if (salt.length === 0) return hmacSha256KeyFirst(new Uint8Array(32), ikm);
  return hmacSha256KeyFirst(salt, ikm);
};

/**
 * HKDF expand step: iteratively produces output from the PRK.
 * Used to expand the 32-byte PRK into arbitrary-length output.
 */
export const hkdfExpand = (prk: Uint8Array, info: Uint8Array, length: number): Uint8Array => {
  const output: number[] = [];
  let previous = new Uint8Array(0);
  let counter = 1;
  while (output.length < length) {
    const input = new Uint8Array(previous.length + info.length + 1);
    input.set(previous, 0);
    input.set(info, previous.length);
    input[input.length - 1] = counter;
    previous = new Uint8Array(hmacSha256KeyFirst(prk, input));
    output.push(...previous);
    counter += 1;
  }
  return new Uint8Array(output.slice(0, length));
};

/**
 * Full HKDF extract-then-expand in one call. The standard KDF used throughout
 * the WhatsApp VoIP key schedule.
 */
export const hkdfExtractAndExpand = (
  key: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number
): Uint8Array => hkdfExpand(hkdfExtract(salt, key), info, length);

/** Convert a 32-bit unsigned integer to little-endian bytes (used for SSRC slot word). */
const uint32ToLittleEndianBytes = (value: number): Uint8Array => {
  const bytes = new Uint8Array(4);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, value >>> 0, true);
  return bytes;
};

/**
 * Derive the WASM participant SSRC for a specific slot.
 *
 * WhatsApp deterministically generates 4 SSRCs per participant from
 * (callId, lid, slotWord). This mirrors the native client so the peer
 * computes the same SSRCs and accepts our media.
 */
export const deriveWasmParticipantSsrc = (
  callId: string, lid: string, slotWord: number
): number => {
  const raw = hkdfExtractAndExpand(
    utf8ToBytes(callId),
    uint32ToLittleEndianBytes(slotWord >>> 0),
    utf8ToBytes(lid),
    4
  );
  return (raw[0]! | (raw[1]! << 8) | (raw[2]! << 16) | ((raw[3]! << 24) >>> 0)) >>> 0;
};

/** The 9 slot words for relay stream SSRC generation — mirrors the native client. */
const WASM_RELAY_STREAM_SLOT_WORDS = [0, 1, 4, 2, 3, 5, 7, 8, 6] as const;

/**
 * Derive all 9 relay stream SSRCs for a participant. Used in the relay
 * private allocate request so the relay knows which SSRCs to forward.
 */
export const deriveWasmRelayStreamSsrcs = (
  callId: string, lid: string
): number[] => WASM_RELAY_STREAM_SLOT_WORDS.map((slotWord) =>
  deriveWasmParticipantSsrc(callId, lid, slotWord)
);

/**
 * Split the base64-encoded raw_e2e material from an accept stanza into
 * the base 32-byte key material and the fingerprint salt tail.
 */
export const splitRawE2E = (encoded: string): RawE2EMaterial => {
  const rawBytes = decodeBase64Bytes(encoded);
  if (rawBytes.length < 32) throw new Error("raw_e2e is shorter than 32 bytes");
  return { rawBytes, baseMaterial: rawBytes.slice(0, 32), fingerprintSalt: rawBytes.slice(32) };
};

/**
 * Derive the fingerprint HMAC from raw_e2e material. Used to verify the
 * peer's certificate fingerprint in 1:1 E2E calls.
 */
export const deriveFingerprintHmac = (
  encodedRawE2E: string, fingerprint: Uint8Array
): Uint8Array => {
  const material = splitRawE2E(encodedRawE2E);
  if (material.fingerprintSalt.length === 0) throw new Error("raw_e2e has no fingerprint salt tail");
  const key = hkdfExtractAndExpand(
    material.baseMaterial, material.fingerprintSalt,
    utf8ToBytes(LabelDataChannelCertFingerprintHmac), 32
  );
  return hmacSha256KeyFirst(key, fingerprint);
};

export const deriveFingerprintHmacHex = (
  encodedRawE2E: string, fingerprintHex: string
): Uint8Array => deriveFingerprintHmac(encodedRawE2E, hexToBytes(fingerprintHex));

/**
 * Derive the SFrame encryption key from raw_e2e material.
 * Used for E2E encryption in group calls above the HBH SRTP layer.
 */
export const deriveE2ESframeKey = (
  encodedRawE2E: string, outputLength = 32
): Uint8Array => {
  const material = splitRawE2E(encodedRawE2E);
  return hkdfExtractAndExpand(
    material.baseMaterial, material.fingerprintSalt,
    utf8ToBytes(LabelE2ESframeKey), outputLength
  );
};

/**
 * Derive arbitrary HBH key material from base + salt + label.
 * Used to generate SRTP and SRTCP key sets for the hop-by-hop path.
 */
export const deriveHbhKeyMaterial = (
  encodedBaseMaterial: string, encodedSalt: string, label: string, outputLength: number
): Uint8Array => {
  const baseMaterial = decodeBase64Bytes(encodedBaseMaterial);
  const salt = decodeBase64Bytes(encodedSalt);
  if (baseMaterial.length === 0) return new Uint8Array(0);
  return hkdfExtractAndExpand(baseMaterial, salt, utf8ToBytes(label), outputLength);
};
