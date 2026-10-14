/**
 * ============================================================================
 * STACK LAYER 3 — Media crypto (1:1 E2E SRTP)
 * ============================================================================
 *
 * End-to-end SRTP for 1:1 calls: HKDF-SHA256 from the shared call key (or
 * raw_e2e), AES-CM PRF to expand session enc/auth/salt, and AES-128-CTR
 * encrypt/decrypt. The sender's device-qualified LID is the HKDF info, so each
 * direction has its own key; no SRTP auth tag is appended (WARP MI handles
 * integrity hop-by-hop).
 *
 * Why: 1:1 calls are end-to-end encrypted between devices, not just to the relay.
 * Using the wrong (bare) LID or the HBH path makes the peer hear garbage. Hands
 * off: same RTP-in / ciphertext-out contract as srtp.ts, selected by the engine
 * when a 1:1 call key is set.
 */
/**
 * SRTP for WhatsApp 1:1 calls (E2E path).
 *
 * Derivation (verified from live native HKDF traces):
 *   ikm      = callKey[16:32] || callKey[0:16]
 *   salt     = nil
 *   info     = senderLid_utf8
 *   material = HKDF-SHA256(ikm, salt=zero32, info, 46)
 *
 * Key layout:
 *   cipherKey = material[0:16]
 *   authKey   = material[16:36]
 *   salt      = material[36:46]
 */
import { createCipheriv, createHmac } from "node:crypto";

import { getRtpHeaderLength } from "../protocol/protocol";
import { readUint16BE, readUint32BE } from "../core/bytes";

const hkdfExtract = (salt: Buffer, ikm: Buffer): Buffer =>
  createHmac("sha256", salt).update(ikm).digest();

const hkdfExpand = (prk: Buffer, info: Buffer, length: number): Buffer => {
  const out = Buffer.alloc(length);
  let block = Buffer.alloc(0);
  let pos = 0;
  let counter = 1;
  while (pos < length) {
    block = createHmac("sha256", prk)
      .update(block)
      .update(info)
      .update(Buffer.from([counter]))
      .digest();
    const take = Math.min(block.length, length - pos);
    block.copy(out, pos, 0, take);
    pos += take;
    counter += 1;
  }
  return out;
};

const hkdf = (
  ikm: Buffer,
  salt: Buffer | null,
  info: Buffer,
  length: number,
): Buffer =>
  hkdfExpand(
    hkdfExtract(salt && salt.length > 0 ? salt : Buffer.alloc(32), ikm),
    info,
    length,
  );

export interface E2ESrtpKeys {
  cipherKey: Buffer; // 16 B  (SRTP *session* encryption key)
  salt: Buffer; // 14 B  (SRTP *session* salt)
  authKey: Buffer; // 20 B  (SRTP *session* auth key — also the WARP MI key)
}

/**
 * libsrtp / RFC 3711 §4.3.1 AES-CM session-key derivation (the SRTP "PRF").
 *
 *   x   = master_salt(14B) with x[7] ^= label
 *   IV  = x || 0x00 0x00                (16-byte AES-CTR counter base, kdr=0)
 *   out = AES-128-CTR(master_key, IV) over `length` zero bytes
 *
 * Labels: 0x00 = SRTP enc key, 0x01 = SRTP auth key, 0x02 = SRTP salt.
 *
 * VERIFIED against a live native-app capture (`.audit-tmp/full_kdf.jsonl`):
 * the derived session enc/salt decrypt the wire Opus exactly, and the
 * session auth key (label 0x01) reproduces every 4-byte WARP MI tag.
 */
const aesCmKdf = (
  masterKey: Buffer,
  masterSalt: Buffer,
  label: number,
  length: number,
): Buffer => {
  if (masterKey.length !== 16) {
    throw new Error(`master_key must be 16 bytes, got ${masterKey.length}`);
  }
  const x = Buffer.alloc(14);
  masterSalt.copy(x, 0, 0, 14);
  x[7] ^= label & 0xff;
  const iv = Buffer.alloc(16);
  x.copy(iv, 0, 0, 14); // bytes 14,15 stay zero (the CM block counter)
  const cipher = createCipheriv("aes-128-ctr", masterKey, iv);
  return Buffer.concat([cipher.update(Buffer.alloc(length)), cipher.final()]);
};

/**
 * Derive E2E SRTP **session** keys for a 1:1 call.
 *
 * The HKDF below produces a 46-byte SRTP *master* block (NOT the final
 * session keys):
 *   master_key  = material[0:16]
 *   master_salt = material[16:30]   (14 bytes)
 *   material[30:46]                 (unused for the active AES_CM_128 profile)
 *
 * The actual session keys used on the wire are then derived from
 * (master_key, master_salt) via the libsrtp AES-CM PRF above. node-load
 * previously used the master block's raw byte ranges directly as the
 * session enc/auth/salt — which is why the peer could never decrypt the
 * audio (silent call) even though signaling/STUN/transport all worked.
 *
 * @param callKey  32-byte plaintext call key from the offer's
 *                 `<destination><to><enc>` (Signal-encrypted to the peer).
 * @param lid      sender LID used as HKDF info. MUST be the device-qualified
 *                 LID the peer associates with this stream (e.g.
 *                 "<user>:<device>@lid"), not the bare LID.
 */
export const deriveE2EKeys = (callKey: Buffer, lid: string): E2ESrtpKeys => {
  // The 1:1 audio E2E SRTP ikm is the 32-byte call key used DIRECTLY — no
  // byte-swap. PROVEN byte-exact against a live native receiver: node-load
  // sent call key b70cce29…2857ad and the native app derived its E2E SRTP
  // master with exactly that ikm (HKDF salt=nil, info=sender device LID, 46).
  // The previous `callKey[16:32]||callKey[0:16]` swap produced a keystream the
  // peer could not reproduce, so the receiver silently dropped every uplink
  // frame (`opus_decode` fired 0×). `raw_e2e` is NOT a separate signaling
  // element under keygen=2: the call key the offerer ships in <enc> *is* the
  // raw_e2e material both sides key audio from.
  const master = hkdf(callKey.subarray(0, 32), null, Buffer.from(lid, "utf8"), 46);
  return deriveE2ESessionKeysFromMaster(master);
};

/**
 * Derive E2E SRTP **session** keys for a 1:1 call from the call's `raw_e2e`
 * material (the version-2 `e2e_keygen` secret the answering device ships in
 * the `<accept>` stanza's `<raw_e2e>` element).
 *
 * Proven byte-exact against a LIVE native macOS WhatsApp call
 * (`.audit-tmp/full_kdf.jsonl`): the native client derives the 1:1 audio SRTP
 * key set as
 *
 *   master = HKDF-SHA256(ikm = raw_e2e[0:32], salt = nil, info = senderLid, 46)
 *
 * and then runs the libsrtp AES-CM PRF (`deriveE2ESessionKeysFromMaster`) over
 * that 46-byte master block. The 32-byte `raw_e2e` is the *natural* byte order
 * of the element (salt(16) || key(16)); it is used here directly as the HKDF
 * ikm, NOT the per-call Signal call key. This is the actual uplink-audio fix:
 * the peer keys every 1:1 audio packet from `raw_e2e`, never from the call key,
 * so deriving from the call key (the previous behaviour) produced a keystream
 * the peer could not reproduce and the receiver silently dropped every frame.
 *
 * `info` MUST be the SENDER's device-qualified LID (e.g.
 * "<user>:<device>@lid"): each direction keys its own stream from the
 * sender's own LID.
 */
export const deriveE2EKeysFromRawE2E = (
  rawE2E: Uint8Array,
  lid: string,
): E2ESrtpKeys => {
  if (rawE2E.length < 32) {
    throw new Error(`raw_e2e must be at least 32 bytes, got ${rawE2E.length}`);
  }
  const ikm = Buffer.from(rawE2E.subarray(0, 32));
  const master = hkdf(ikm, null, Buffer.from(lid, "utf8"), 46);
  return deriveE2ESessionKeysFromMaster(master);
};

/**
 * Derive the SRTP session keys from an already-expanded 46-byte E2E master
 * block. Split out so it can be unit-tested directly against captured
 * native-app key material (see `test/srtp1to1.test.mts`).
 */
export const deriveE2ESessionKeysFromMaster = (master: Buffer): E2ESrtpKeys => {
  const masterKey = master.subarray(0, 16);
  const masterSalt = master.subarray(16, 30); // 14 bytes
  return {
    cipherKey: aesCmKdf(masterKey, masterSalt, 0x00, 16),
    authKey: aesCmKdf(masterKey, masterSalt, 0x01, 20),
    salt: aesCmKdf(masterKey, masterSalt, 0x02, 14),
  };
};

/**
 * Build the AES-128-CTR initialisation vector per RFC 3711 §4.1.1:
 *   IV = (salt[0..14] || 00 00) XOR (00 00 00 00 || SSRC || ROC*0x10000+seq)
 *
 * `packet_index` is a 48-bit big-endian value made of `(roc << 16) | seq`.
 * We split it into hi16 + lo32 to stay within JS's safe-integer range.
 */
const buildSrtpIV = (
  salt: Buffer,
  ssrc: number,
  roc: number,
  seq: number,
): Buffer => {
  const iv = Buffer.alloc(16);
  if (salt.length > 14) {
    throw new Error(`SRTP salt must be at most 14 bytes, got ${salt.length}`);
  }
  salt.copy(iv, 14 - salt.length, 0, salt.length);
  iv[4] ^= (ssrc >>> 24) & 0xff;
  iv[5] ^= (ssrc >>> 16) & 0xff;
  iv[6] ^= (ssrc >>> 8) & 0xff;
  iv[7] ^= ssrc & 0xff;
  const packetIndex = roc * 0x10000 + (seq & 0xffff);
  const hi16 = Math.floor(packetIndex / 0x100000000) & 0xffff;
  const lo32 = packetIndex & 0xffffffff;
  iv[8] ^= (hi16 >>> 8) & 0xff;
  iv[9] ^= hi16 & 0xff;
  iv[10] ^= (lo32 >>> 24) & 0xff;
  iv[11] ^= (lo32 >>> 16) & 0xff;
  iv[12] ^= (lo32 >>> 8) & 0xff;
  iv[13] ^= lo32 & 0xff;
  return iv;
};

/**
 * Encrypt or decrypt the SRTP payload (header is untouched). Counter mode
 * is symmetric so encrypt and decrypt are the same operation.
 */
export const cryptSrtpPayload = (
  keys: Pick<E2ESrtpKeys, "cipherKey" | "salt">,
  ssrc: number,
  seq: number,
  roc: number,
  payload: Buffer,
): Buffer => {
  const iv = buildSrtpIV(keys.salt, ssrc, roc, seq);
  const cipher = createCipheriv("aes-128-ctr", keys.cipherKey, iv);
  return Buffer.concat([cipher.update(payload), cipher.final()]);
};

/**
 * Encrypt an entire RTP packet in place: header bytes stay untouched, the
 * payload (everything after the RTP header) is replaced with its
 * AES-CTR-encrypted equivalent. No auth tag is appended.
 */
export const protectRtp1to1 = (
  keys: Pick<E2ESrtpKeys, "cipherKey" | "salt">,
  packet: Buffer,
  roc: number,
): Buffer => {
  const headerLen = getRtpHeaderLength(packet);
  const seq = readUint16BE(packet, 2);
  const ssrc = readUint32BE(packet, 8);
  const header = packet.subarray(0, headerLen);
  const payload = packet.subarray(headerLen);
  const ciphertext = cryptSrtpPayload(keys, ssrc, seq, roc, payload);
  return Buffer.concat([header, ciphertext]);
};

/**
 * Decrypt a captured 1:1 SRTP packet. Returns the cleartext RTP packet
 * (header + cleartext payload).
 */
export const unprotectRtp1to1 = (
  keys: Pick<E2ESrtpKeys, "cipherKey" | "salt">,
  packet: Buffer,
  roc: number,
): Buffer => {
  // Counter mode is symmetric.
  return protectRtp1to1(keys, packet, roc);
};
