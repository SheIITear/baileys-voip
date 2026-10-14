/**
 * ============================================================================
 * STACK LAYER 4 — RTP framing (WARP extension)
 * ============================================================================
 *
 * WhatsApp's proprietary WARP RTP extension (profile 0xDEBE): the empty vs
 * audio-piggyback extension words, and the 4-byte (warp_mi_tag_len) message-
 * integrity tag = HMAC-SHA1(auth_key, header||ext||ciphertext||ROC_BE32).
 *
 * Why: the relay rejects/ignores audio RTP that lacks the expected WARP ext and
 * MI tag. Hands off: rtpEngine builds the RTP header + this ext; srtp/srtp1to1
 * compute the tag over the protected payload.
 */
/**
 * WARP transport framing for WhatsApp VoIP.
 *
 * Every WhatsApp 1:1 *and* group audio packet that goes to/from the relay is
 * a "WARP" packet, not a plain SRTP packet. The wire shape (verified live
 * against the macOS native app via CommonCrypto + sendto Frida hooks — see
 * `.audit-tmp/cc_capture.jsonl`, `wasm_packets.jsonl`) is:
 *
 *   [ RTP-12 header ]
 *   [ 0xDEBE WARP extension  (profile 0xDEBE, N 32-bit words) ]
 *   [ AES-128-CTR ciphertext (length == cleartext Opus length) ]
 *   [ WARP message-integrity (MI) tag, `warp_mi_tag_len` bytes ]
 *
 * Key framing details:
 *
 *   1. The WARP **audio-piggyback extension**. The native client starts a
 *      call emitting `debe 0000` (empty extension) for the first couple of
 *      packets, then the "audio piggyback extender" turns on
 *      (`audio_piggyback_extender_set_enable` in the wasm) and from then on
 *      *every* audio packet carries a one-word extension:
 *
 *          de be 00 01    <- profile 0xDEBE, length = 1 word
 *          30 01 00 00    <- RFC 8285 one-byte header ext, id=3, len=1,
 *                            value=0x00, padded to a 32-bit word
 *
 *      Ground truth (cc_capture.jsonl): packets #1/#2 -> `debe0000`,
 *      packets #3.. -> `debe000130010000`, regardless of frame size.
 *
 *   2. The 4-byte trailer is the WARP **message-integrity tag**, not an
 *      SRTP auth tag in the IETF sense. It is `HMAC-SHA1(auth_key,
 *      header || ext || ciphertext || ROC_BE32)[0:warp_mi_tag_len]`. The
 *      `auth_key` is the SRTP auth key of whichever context owns the hop
 *      (the E2E SRTP auth key for the 1:1 path, the HBH SRTP auth key for
 *      the relay/group path). `SrtpContext.protectRtp` already computes this
 *      exact value when `authTagLength = warp_mi_tag_len`; the helpers here
 *      exist so the framing is documented and unit-testable in isolation.
 */
import { createHmac } from "node:crypto";

import { concatBytes, readUint16BE, uint32ToBytes } from "../core/bytes";
import { getRtpHeaderLength } from "../protocol/protocol";

/** WhatsApp-proprietary RTP header-extension profile (NOT RFC 8285 0xBEDE). */
export const WARP_EXT_PROFILE = 0xdebe;

/**
 * The audio-piggyback extension body: a single RFC 8285 one-byte-header
 * extension element `id=3, len=1, value=0x00`, zero-padded to one 32-bit
 * word. This is what the native client appends once the piggyback extender
 * is enabled. Emitted as the 4 bytes that follow the `debe 0001` ext header.
 */
export const WARP_AUDIO_PIGGYBACK_EXT = new Uint8Array([0x30, 0x01, 0x00, 0x00]);

/** Default `warp_mi_tag_len` advertised by relays for 1:1 audio. */
export const WARP_MI_TAG_LEN = 4;

/**
 * Number of leading packets the native client sends with the empty
 * `debe 0000` extension before the audio-piggyback extender switches on.
 * Verified value: 2 (packets #1 and #2 are empty, #3 onward carry the ext).
 */
export const WARP_PIGGYBACK_START_PACKET = 2;

const EMPTY = new Uint8Array(0);

/**
 * Choose the WARP extension body for the `packetIndex`-th outbound audio
 * packet (0-based). Returns the audio-piggyback word once the extender is
 * enabled, otherwise an empty body (which still renders as `debe 0000`).
 */
export const audioPiggybackExtensionFor = (
  packetIndex: number,
  enabled = true,
  startPacket = WARP_PIGGYBACK_START_PACKET,
): Uint8Array =>
  enabled && packetIndex >= startPacket ? WARP_AUDIO_PIGGYBACK_EXT : EMPTY;

/**
 * Compute the WARP message-integrity tag for an already-assembled,
 * already-encrypted RTP/WARP packet (header + ext + ciphertext, NO tag).
 *
 *   tag = HMAC-SHA1(authKey, packet || ROC_BE32)[0 : tagLen]
 */
export const computeWarpMiTag = (
  authKey: Uint8Array,
  packetWithoutTag: Uint8Array,
  roc: number,
  tagLen: number = WARP_MI_TAG_LEN,
): Uint8Array => {
  const rocBytes = uint32ToBytes(roc >>> 0);
  const mac = createHmac("sha1", Buffer.from(authKey))
    .update(Buffer.from(packetWithoutTag))
    .update(Buffer.from(rocBytes))
    .digest();
  return new Uint8Array(mac.subarray(0, tagLen));
};

/** Append the WARP MI tag to a packet. */
export const appendWarpMiTag = (
  authKey: Uint8Array,
  packetWithoutTag: Uint8Array,
  roc: number,
  tagLen: number = WARP_MI_TAG_LEN,
): Uint8Array =>
  concatBytes(packetWithoutTag, computeWarpMiTag(authKey, packetWithoutTag, roc, tagLen));

export interface WarpPacketView {
  /** Offset where the RTP header + WARP extension end and ciphertext begins. */
  headerLength: number;
  /** Extension profile (expected 0xDEBE) or null when X-bit is clear. */
  extensionProfile: number | null;
  /** Raw extension body bytes (the 32-bit words after the ext header). */
  extensionData: Uint8Array;
  /** True when the audio-piggyback element (id=3) is present. */
  hasAudioPiggyback: boolean;
  /** Ciphertext (Opus) region, tag stripped. */
  ciphertext: Uint8Array;
  /** The trailing WARP MI tag. */
  miTag: Uint8Array;
}

/**
 * Parse a received WARP packet into its regions. `tagLen` defaults to 4.
 * Does NOT verify the MI tag or decrypt — callers feed `ciphertext` to the
 * SRTP context and (optionally) check `miTag` with {@link computeWarpMiTag}.
 */
export const parseWarpPacket = (
  packet: Uint8Array,
  tagLen: number = WARP_MI_TAG_LEN,
): WarpPacketView => {
  if (packet.length < 12 + tagLen) {
    throw new Error("WARP packet too short");
  }
  const headerLength = getRtpHeaderLength(packet);
  const hasExtension = (packet[0]! & 0x10) !== 0;
  let extensionProfile: number | null = null;
  let extensionData = EMPTY;
  if (hasExtension) {
    const cc = packet[0]! & 0x0f;
    const extHeaderOffset = 12 + cc * 4;
    extensionProfile = readUint16BE(packet, extHeaderOffset);
    extensionData = packet.slice(extHeaderOffset + 4, headerLength);
  }
  const miTag = packet.slice(packet.length - tagLen);
  const ciphertext = packet.slice(headerLength, packet.length - tagLen);
  return {
    headerLength,
    extensionProfile,
    extensionData,
    hasAudioPiggyback: containsAudioPiggyback(extensionData),
    ciphertext,
    miTag,
  };
};

/** Scan an RFC 8285 one-byte-header extension body for the id=3 element. */
export const containsAudioPiggyback = (extensionData: Uint8Array): boolean => {
  let offset = 0;
  while (offset < extensionData.length) {
    const byte = extensionData[offset]!;
    if (byte === 0x00) {
      offset += 1; // padding
      continue;
    }
    const id = byte >> 4;
    const len = (byte & 0x0f) + 1;
    if (id === 3) {
      return true;
    }
    offset += 1 + len;
  }
  return false;
};
