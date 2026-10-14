/**
 * ============================================================================
 * STACK LAYER 3 — Media crypto (SFrame, E2E group)
 * ============================================================================
 *
 * Per-frame AES-GCM encryption for E2E group calls: 64-bit monotonic counter,
 * 32-bit key id, optional AAD, key derived from raw_e2e via HKDF, nonce per the
 * IETF SFrame draft.
 *
 * Why: group E2E protects each media frame end-to-end above the SRTP hop-by-hop
 * layer. Hands off: wraps/unwraps the codec payload before SRTP framing.
 */
/**
 * SFrame (Secure Frame) media encryption context for WhatsApp E2E group calls.
 *
 * Implements AES-GCM (128 or 256 bit) per-frame encryption/decryption with a
 * monotonically-increasing 64-bit counter, 32-bit key ID, and optional AAD
 * (additional authenticated data) segment. The key is derived from the call's
 * raw_e2e material via HKDF and the counter-based nonce construction matches
 * the IETF SFrame draft layout.
 */

import {
  createCipheriv,
  createDecipheriv,
  type CipherGCM,
  type DecipherGCM,
} from "node:crypto";
import { concatBytes, ensureLength, readUint32BE, uint32ToBytes, uint64ToBytes } from "../core/bytes";

const resolveAlgorithm = (key: Uint8Array): string => {
  if (key.length >= 32) {
    return "aes-256-gcm";
  }
  if (key.length >= 16) {
    return "aes-128-gcm";
  }
  throw new Error("SFrame key must be at least 16 bytes");
};

const buildNonce = (keyId: number, counter: bigint): Uint8Array =>
  concatBytes(uint32ToBytes(keyId >>> 0), uint64ToBytes(counter));

export class SframeContext {
  #key: Uint8Array;
  #keyId: number;
  #counter: bigint;
  #algorithm: string;

  constructor(key: Uint8Array, keyId = 0, initialCounter = 1n) {
    this.#key = key;
    this.#keyId = keyId >>> 0;
    this.#counter = initialCounter;
    this.#algorithm = resolveAlgorithm(key);
  }

  encrypt(payload: Uint8Array, aad = new Uint8Array(0)): Uint8Array {
    const counter = this.#counter;
    this.#counter += 1n;
    const header = concatBytes(new Uint8Array([1]), uint32ToBytes(this.#keyId), uint64ToBytes(counter));
    const nonce = buildNonce(this.#keyId, counter);
    ensureLength(nonce, 12, "SFrame nonce");
    const cipher = createCipheriv(
      this.#algorithm,
      this.#key.slice(0, this.#algorithm.includes("256") ? 32 : 16),
      nonce,
    ) as CipherGCM;
    cipher.setAAD(concatBytes(header, aad));
    const ciphertext = Buffer.concat([cipher.update(payload), cipher.final()]);
    const tag = cipher.getAuthTag();
    return concatBytes(header, new Uint8Array(ciphertext), new Uint8Array(tag));
  }

  decrypt(frame: Uint8Array, aad = new Uint8Array(0)): Uint8Array {
    if (frame.length < 1 + 4 + 8 + 16) throw new Error("SFrame packet too short");
    const headerLength = 13;
    const header = frame.slice(0, headerLength);
    const keyId = readUint32BE(header, 1);
    if (keyId !== this.#keyId) throw new Error(`unexpected SFrame key id ${keyId}`);
    const nonce = header.slice(1);
    const tag = frame.slice(frame.length - 16);
    const ciphertext = frame.slice(headerLength, frame.length - 16);
    const decipher = createDecipheriv(
      this.#algorithm,
      this.#key.slice(0, this.#algorithm.includes("256") ? 32 : 16),
      nonce,
    ) as DecipherGCM;
    decipher.setAAD(concatBytes(header, aad));
    decipher.setAuthTag(Buffer.from(tag));
    return new Uint8Array(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
  }
}
