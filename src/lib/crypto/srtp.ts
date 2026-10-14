/**
 * ============================================================================
 * STACK LAYER 3 — Media crypto (hop-by-hop SRTP)
 * ============================================================================
 *
 * Hop-by-hop SRTP for group calls: AES-128-CTR payload encryption plus
 * HMAC-SHA1 authentication, with the two-stage HKDF cascade that derives the
 * SRTP/SRTCP key sets and the 14-byte master salt. Tracks the per-SSRC IV
 * construction (RFC 3711) and appends the WARP message-integrity tag.
 *
 * Why: group media is protected hop-by-hop to the relay. Hands off: protects RTP
 * produced by rtpEngine (layer 4) before it goes to the relay, and unprotects
 * inbound RTP before it reaches the decoder.
 */
/**
 * SRTP (Secure Real-time Transport Protocol) implementation for WhatsApp VoIP.
 *
 * Provides encrypt/unprotect for RTP and RTCP packets using AES-128-CTR with
 * session keys derived from the libsrtp AES-CM PRF. Supports both the hop-by-hop
 * (HBH, group call) path with HMAC-SHA1 auth tags and the end-to-end (E2E, 1:1
 * call) path where auth tag verification is optional (the WARP MI tag is handled
 * separately). Includes the two-stage HKDF cascade for deriving HBH SRTP secrets
 * from the relay transport key/salt material.
 */

import { createCipheriv, timingSafeEqual } from "node:crypto";
import {
  LabelDownlinkHbhSrtcpSalt,
  LabelDownlinkHbhSrtcpKey,
  LabelHbhSrtpSalt,
  LabelHbhSrtpKey,
  LabelUplinkHbhSrtcpSalt,
  LabelUplinkHbhSrtcpKey,
  hkdfExtractAndExpand,
  hmacSha1KeyFirst,
} from "../core/crypto";
import {
  concatBytes,
  decodeBase64Bytes,
  ensureLength,
  readUint16BE,
  readUint32BE,
  uint32ToBytes,
  uint48ToBytes,
  writeUint32BE,
  utf8ToBytes,
} from "../core/bytes";
import { getRtpHeaderLength } from "../protocol/protocol";

export interface SrtpKeySet {
  encryptionKey: Uint8Array;
  authenticationKey: Uint8Array;
  salt: Uint8Array;
}

export interface HbhSrtpSecrets {
  srtp: SrtpKeySet;
  uplinkSrtcp: SrtpKeySet;
  downlinkSrtcp: SrtpKeySet;
}

const splitHbhKeySet = (keyMaterial: Uint8Array, saltMaterial: Uint8Array): SrtpKeySet => {
  if (keyMaterial.length < 30) {
    throw new Error("HBH SRTP key material must be at least 30 bytes");
  }
  if (saltMaterial.length < 14) {
    throw new Error("HBH SRTP salt material must be at least 14 bytes");
  }
  return {
    encryptionKey: keyMaterial.slice(0, 16),
    authenticationKey: keyMaterial.slice(16, 30),
    salt: saltMaterial.slice(0, 14),
  };
};

/**
 * Derive HBH key set using the two-stage cascade verified from the native app:
 * Stage 1: salt = HKDF(ikm=saltBase, salt=zeros, info=saltLabel, outLen=32)
 * Stage 2: key = HKDF(ikm=keyBase, salt=salt_from_stage1, info=keyLabel, outLen=30)
 * 
 * The 30-byte key is split as: enc[16] || auth[14]
 * The 32-byte salt is truncated to 14 bytes for SRTP master salt.
 */
const deriveHbhKeySet = (
  encodedBaseMaterial: string,
  encodedSalt: string,
  saltLabel: string,
  keyLabel: string
): SrtpKeySet => {
  const keyBase = decodeBase64Bytes(encodedBaseMaterial);
  const saltBase = decodeBase64Bytes(encodedSalt);
  if (keyBase.length === 0 || saltBase.length === 0) {
    return {
      encryptionKey: new Uint8Array(0),
      authenticationKey: new Uint8Array(0),
      salt: new Uint8Array(0),
    };
  }

  // Stage 1: Derive salt-base using zero salt
  const saltMaterial = hkdfExtractAndExpand(
    saltBase,
    new Uint8Array(32),
    utf8ToBytes(saltLabel),
    32
  );
  
  // Stage 2: Derive key material using the salt from stage 1
  const keyMaterial = hkdfExtractAndExpand(
    keyBase,
    saltMaterial,
    utf8ToBytes(keyLabel),
    30
  );
  
  return splitHbhKeySet(keyMaterial, saltMaterial);
};

export const deriveHbhSrtpSecrets = (
  encodedBaseMaterial: string,
  encodedSalt: string
): HbhSrtpSecrets => ({
  srtp: deriveHbhKeySet(
    encodedBaseMaterial,
    encodedSalt,
    LabelHbhSrtpSalt,
    LabelHbhSrtpKey
  ),
  uplinkSrtcp: deriveHbhKeySet(
    encodedBaseMaterial,
    encodedSalt,
    LabelUplinkHbhSrtcpSalt,
    LabelUplinkHbhSrtcpKey
  ),
  downlinkSrtcp: deriveHbhKeySet(
    encodedBaseMaterial,
    encodedSalt,
    LabelDownlinkHbhSrtcpSalt,
    LabelDownlinkHbhSrtcpKey
  ),
});

const aesCtrCrypt = (
  key: Uint8Array,
  iv: Uint8Array,
  payload: Uint8Array
): Uint8Array => {
  const cipher = createCipheriv(`aes-${key.length * 8}-ctr`, key, iv);
  return new Uint8Array(
    Buffer.concat([cipher.update(payload), cipher.final()])
  );
};

const buildRtpIv = (
  salt: Uint8Array,
  ssrc: number,
  packetIndex: bigint
): Uint8Array => {
  if (salt.length === 0 || salt.length > 14) {
    throw new Error(`SRTP salt must be 1..14 bytes, got ${salt.length}`);
  }
  const iv = new Uint8Array(16);
  // Right-align the salt in the 14-byte field (bytes 0..13).
  // WhatsApp's E2E and HBH paths both use a 14-byte SRTP *session* salt
  // (derived via the libsrtp AES-CM PRF), so it fills bytes 0..13 — the
  // standard RFC 3711 layout. (Shorter salts are right-aligned for safety,
  // but the active profile always supplies 14 bytes.)
  iv.set(salt, 14 - salt.length);

  const ssrcBytes = uint32ToBytes(ssrc >>> 0);
  for (let index = 0; index < 4; index += 1) {
    iv[4 + index] ^= ssrcBytes[index]!;
  }

  const packetIndexBytes = uint48ToBytes(packetIndex);
  for (let index = 0; index < 6; index += 1) {
    iv[8 + index] ^= packetIndexBytes[index]!;
  }

  return iv;
};

const buildRtcpIv = (
  salt: Uint8Array,
  ssrc: number,
  index: number
): Uint8Array => buildRtpIv(salt, ssrc, BigInt(index >>> 0));

const computeAuthTag = (
  authKey: Uint8Array,
  packet: Uint8Array,
  indexBytes: Uint8Array,
  length: number
): Uint8Array => hmacSha1KeyFirst(authKey, concatBytes(packet, indexBytes)).slice(0, length);

export interface UnprotectedRtcp {
  packet: Uint8Array;
  index: number;
}

export class SrtpContext {
  #srtp: SrtpKeySet;
  #srtcp: SrtpKeySet;
  #authTagLength: number;
  #verifyRtpAuth: boolean;

  constructor({
    srtp,
    srtcp,
    authTagLength = 10,
    verifyRtpAuth = true,
  }: {
    srtp: SrtpKeySet;
    srtcp: SrtpKeySet;
    authTagLength?: number;
    verifyRtpAuth?: boolean;
  }) {
    this.#srtp = srtp;
    this.#srtcp = srtcp;
    this.#authTagLength = authTagLength;
    this.#verifyRtpAuth = verifyRtpAuth;
  }

  protectRtp(packet: Uint8Array, roc = 0): Uint8Array {
    const headerLength = getRtpHeaderLength(packet);
    const header = packet.slice(0, headerLength);
    const payload = packet.slice(headerLength);
    const sequenceNumber = readUint16BE(packet, 2);
    const ssrc = readUint32BE(packet, 8);
    const packetIndex = (BigInt(roc >>> 0) << 16n) | BigInt(sequenceNumber);
    const iv = buildRtpIv(this.#srtp.salt, ssrc, packetIndex);
    const encryptedPayload = aesCtrCrypt(this.#srtp.encryptionKey, iv, payload);
    const protectedPacket = concatBytes(header, encryptedPayload);
    if (this.#authTagLength === 0) {
      return protectedPacket;
    }
    const rocBytes = uint32ToBytes(roc >>> 0);
    const tag = computeAuthTag(
      this.#srtp.authenticationKey,
      protectedPacket,
      rocBytes,
      this.#authTagLength,
    );
    return concatBytes(protectedPacket, tag);
  }

  verifyRtpAuthTag(packet: Uint8Array, roc = 0): boolean | null {
    if (this.#authTagLength === 0) return null;
    if (packet.length < 12 + this.#authTagLength) return false;
    const protectedPacket = packet.slice(0, packet.length - this.#authTagLength);
    const receivedTag = packet.slice(packet.length - this.#authTagLength);
    const expectedTag = computeAuthTag(
      this.#srtp.authenticationKey,
      protectedPacket,
      uint32ToBytes(roc >>> 0),
      this.#authTagLength,
    );
    return (
      receivedTag.length === expectedTag.length &&
      timingSafeEqual(Buffer.from(receivedTag), Buffer.from(expectedTag))
    );
  }

  unprotectRtp(packet: Uint8Array, roc = 0): Uint8Array {
    if (packet.length < 12 + this.#authTagLength) throw new Error("SRTP packet too short");
    let protectedPacket: Uint8Array;
    if (this.#authTagLength === 0) {
      protectedPacket = packet;
    } else {
      protectedPacket = packet.slice(0, packet.length - this.#authTagLength);
      if (this.#verifyRtpAuth) {
        const receivedTag = packet.slice(packet.length - this.#authTagLength);
        const rocBytes = uint32ToBytes(roc);
        const expectedTag = computeAuthTag(
          this.#srtp.authenticationKey,
          protectedPacket,
          rocBytes,
          this.#authTagLength,
        );
        if (
          receivedTag.length !== expectedTag.length ||
          !timingSafeEqual(Buffer.from(receivedTag), Buffer.from(expectedTag))
        ) {
          throw new Error("SRTP authentication failed");
        }
      }
    }

    const headerLength = getRtpHeaderLength(protectedPacket);
    const header = protectedPacket.slice(0, headerLength);
    const encryptedPayload = protectedPacket.slice(headerLength);
    const sequenceNumber = readUint16BE(protectedPacket, 2);
    const ssrc = readUint32BE(protectedPacket, 8);
    const packetIndex = (BigInt(roc) << 16n) | BigInt(sequenceNumber);
    const iv = buildRtpIv(this.#srtp.salt, ssrc, packetIndex);
    const payload = aesCtrCrypt(this.#srtp.encryptionKey, iv, encryptedPayload);
    return concatBytes(header, payload);
  }

  protectRtcp(packet: Uint8Array, index = 0): Uint8Array {
    if (packet.length < 8) throw new Error("SRTCP packet too short");
    const header = packet.slice(0, 8);
    const body = packet.slice(8);
    const ssrc = readUint32BE(packet, 4);
    const iv = buildRtcpIv(this.#srtcp.salt, ssrc, index);
    const encryptedBody = aesCtrCrypt(this.#srtcp.encryptionKey, iv, body);
    const protectedPacket = concatBytes(header, encryptedBody);
    const indexField = new Uint8Array(4);
    writeUint32BE(indexField, 0, (index >>> 0) | 0x80000000);
    const tag = computeAuthTag(
      this.#srtcp.authenticationKey,
      protectedPacket,
      indexField,
      this.#authTagLength,
    );
    return concatBytes(protectedPacket, indexField, tag);
  }

  unprotectRtcp(packet: Uint8Array): UnprotectedRtcp {
    if (packet.length < 12 + this.#authTagLength) throw new Error("SRTCP packet too short");
    const authStart = packet.length - this.#authTagLength;
    const indexStart = authStart - 4;
    const protectedPacket = packet.slice(0, indexStart);
    const indexField = packet.slice(indexStart, authStart);
    const receivedTag = packet.slice(authStart);
    const expectedTag = computeAuthTag(
      this.#srtcp.authenticationKey,
      protectedPacket,
      indexField,
      this.#authTagLength,
    );
    if (
      receivedTag.length !== expectedTag.length ||
      !timingSafeEqual(Buffer.from(receivedTag), Buffer.from(expectedTag))
    ) {
      throw new Error("SRTCP authentication failed");
    }

    const index = readUint32BE(indexField, 0) & 0x7fffffff;
    const header = protectedPacket.slice(0, 8);
    const encryptedBody = protectedPacket.slice(8);
    const ssrc = readUint32BE(protectedPacket, 4);
    const iv = buildRtcpIv(this.#srtcp.salt, ssrc, index);
    const body = aesCtrCrypt(this.#srtcp.encryptionKey, iv, encryptedBody);
    return { packet: concatBytes(header, body), index };
  }
}
