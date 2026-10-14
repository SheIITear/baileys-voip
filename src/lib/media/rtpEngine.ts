/**
 * ============================================================================
 * STACK LAYER 4 — RTP framing (send/receive engines)
 * ============================================================================
 *
 * Owns the per-SSRC RTP state: sequence number, RTP timestamp (48 kHz Opus
 * clock), SSRC, and the SRTP rollover counter (ROC). `packetize()` assembles the
 * RTP header + WARP extension, advances the timestamp by the frame's sample step
 * (supports an explicit per-packet step for the variable/constant MLow case), and
 * hands the packet to the SRTP layer; the receive engine tracks ROC on inbound.
 *
 * Why: correct seq/timestamp/ROC are required for the peer to order frames and
 * for the AES-CTR IV to match. Hands off: down to srtp (layer 3), up from the
 * encoder (layer 5) via mediaPipeline.
 */
/**
 * RTP send/receive engines that own the per-SSRC sequence number, RTP
 * timestamp, and SRTP rollover counter (ROC) state. The engines wrap the
 * existing `SrtpContext` so callers can stay agnostic of the SRTP framing
 * details — they hand in cleartext Opus bytes (or get cleartext payloads
 * out) and the engine takes care of packetization, encryption, and ROC
 * tracking across the 16-bit sequence number wrap.
 *
 * The engine is intentionally synchronous so it can be exercised from
 * deterministic tests without coordinating with `dgram` or ffmpeg pipes.
 */
import {
  buildRtcpSenderReport,
  buildRtcpSourceDescription,
  buildRtpPacket,
  buildWarpApplicationFeedback,
  buildWarpStreamHello,
  buildWarpTransportFeedback,
  parseRtp,
} from "../protocol/protocol";
import { readUint16BE, readUint32BE } from "../core/bytes";
import { SrtpContext } from "../crypto/srtp";
import {
  WARP_PIGGYBACK_START_PACKET,
  audioPiggybackExtensionFor,
} from "../crypto/warp";
import { traceMediaPacket, traceRelayPacket } from "../app/trace";
import { diagTx, diagRx } from "../app/diag";

const DEFAULT_OPUS_PAYLOAD_TYPE = 120;
const DEFAULT_SAMPLE_RATE = 48_000;
const DEFAULT_FRAME_DURATION_MS = 20;
const DEFAULT_EXTENSION_PROFILE = 0xdebe;

/**
 * Default RFC 8285 RTP header extension contents for the audio stream. The
 * stream carries the extension profile `0xdebe` with a zero-length body (the
 * 4-byte extension header only). A non-empty body such as `30010000` selects
 * the audio piggyback form, which the receiver does not expect on this stream
 * and which causes it to stop playing the audio.
 */
const DEFAULT_AUDIO_EXTENSION_DATA = new Uint8Array(0);

const computeSamplesPerFrame = (sampleRate: number, frameDurationMs: number) =>
  Math.max(
    1,
    Math.round((sampleRate * frameDurationMs) / 1000),
  );

const buildNtpTimestamp = (): { most: number; least: number } => {
  const epoch = Date.now() + 2208988800000;
  const seconds = Math.floor(epoch / 1000);
  const fraction = Math.round(((epoch % 1000) / 1000) * 0x100000000);
  return { most: seconds >>> 0, least: fraction >>> 0 };
};

export interface RtpSendEngineOptions {
  ssrc: number;
  payloadType?: number;
  sampleRate?: number;
  frameDurationMs?: number;
  extensionProfile?: number;
  extensionData?: Uint8Array;
  /**
   * Emit the WARP audio-piggyback extension (`debe0001 / 30 01 00 00`) once
   * the extender turns on. Matches the native client, which sends an empty
   * `debe0000` extension for the first `piggybackStartPacket` packets and
   * then carries the piggyback word on every subsequent audio packet.
   * Defaults to true. Ignored when `extensionData` is given explicitly.
   */
  audioPiggyback?: boolean;
  /** Packet index (0-based) at which the piggyback extender turns on (default 2). */
  piggybackStartPacket?: number;
  initialSequenceNumber?: number;
  initialTimestamp?: number;
  cname?: string;
  trace?: boolean;
}

/**
 * RTP transmit engine for a single SSRC. Each call to `packetize()` advances
 * the sequence number by 1 and the RTP timestamp by `samplesPerFrame`,
 * which is how Opus 20/40/60 ms frames are timestamped on the wire.
 */
export class RtpSendEngine {
  readonly ssrc: number;
  readonly payloadType: number;
  readonly sampleRate: number;
  readonly frameDurationMs: number;
  readonly samplesPerFrame: number;
  readonly extensionProfile: number;
  readonly extensionData: Uint8Array;
  #explicitExtensionData: boolean;
  #audioPiggyback: boolean;
  #piggybackStartPacket: number;

  #srtp: SrtpContext;
  #sequenceNumber: number;
  #timestamp: number;
  #roc = 0;
  #packetCount = 0;
  #octetCount = 0;
  #rtcpIndex = 0;
  #traceEnabled: boolean;
  #cname: string;

  constructor(srtp: SrtpContext, options: RtpSendEngineOptions) {
    if (!options || typeof options.ssrc !== "number") {
      throw new Error("RtpSendEngine requires options.ssrc");
    }
    this.#srtp = srtp;
    this.ssrc = options.ssrc >>> 0;
    this.payloadType = options.payloadType ?? DEFAULT_OPUS_PAYLOAD_TYPE;
    this.sampleRate = options.sampleRate ?? DEFAULT_SAMPLE_RATE;
    this.frameDurationMs = options.frameDurationMs ?? DEFAULT_FRAME_DURATION_MS;
    this.samplesPerFrame = computeSamplesPerFrame(this.sampleRate, this.frameDurationMs);
    this.extensionProfile = options.extensionProfile ?? DEFAULT_EXTENSION_PROFILE;
    this.extensionData = options.extensionData ?? DEFAULT_AUDIO_EXTENSION_DATA;
    this.#explicitExtensionData = options.extensionData !== undefined;
    this.#audioPiggyback = options.audioPiggyback !== false;
    this.#piggybackStartPacket = options.piggybackStartPacket ?? WARP_PIGGYBACK_START_PACKET;
    this.#sequenceNumber = (options.initialSequenceNumber ?? 0) & 0xffff;
    this.#timestamp = (options.initialTimestamp ?? 0) >>> 0;
    this.#cname = options.cname ?? `node-load-${this.ssrc.toString(16)}`;
    this.#traceEnabled = options.trace !== false;
  }

  /**
   * Build and SRTP-protect an RTP packet wrapping `opusBytes`. The engine
   * advances its sequence-number and timestamp counters, and bumps the
   * ROC when the 16-bit sequence number wraps.
   */
  packetize(
    opusBytes: Uint8Array,
    timestampStepFrames = 1,
    explicitSampleStep?: number,
  ): Uint8Array {
    const sequenceNumber = this.#sequenceNumber;
    const timestamp = this.#timestamp;
    const stepFrames = Math.max(1, Math.floor(timestampStepFrames));
    const extensionData = this.#explicitExtensionData
      ? this.extensionData
      : audioPiggybackExtensionFor(this.#packetCount, this.#audioPiggyback, this.#piggybackStartPacket);
    const packet = buildRtpPacket({
      payloadType: this.payloadType,
      sequenceNumber,
      timestamp,
      ssrc: this.ssrc,
      extensionProfile: this.extensionProfile,
      extensionData,
      payload: opusBytes,
    });
    const protectedPacket = this.#srtp.protectRtp(packet, this.#roc);
    let selfDecryptOk = false;
    let selfDecryptError: string | undefined;
    if (this.#traceEnabled) {
      try {
        const decrypted = this.#srtp.unprotectRtp(protectedPacket, this.#roc);
        const parsed = parseRtp(decrypted);
        selfDecryptOk =
          parsed.payload.length === opusBytes.length &&
          parsed.payload.every((value, index) => value === opusBytes[index]);
        traceMediaPacket("srtp_self_decrypt", decrypted, {
          ssrc: this.ssrc,
          sequenceNumber,
          timestamp,
          roc: this.#roc,
          payloadType: parsed.payloadType,
          payloadLength: parsed.payload.length,
          opusToc: parsed.payload[0] ?? null,
          matchesInputPayload: selfDecryptOk,
        });
      } catch (error) {
        selfDecryptError = String(error);
        traceMediaPacket("srtp_self_decrypt", new Uint8Array(0), {
          ssrc: this.ssrc,
          sequenceNumber,
          timestamp,
          roc: this.#roc,
          matchesInputPayload: false,
          error: selfDecryptError,
        });
      }
    }

    this.#packetCount = (this.#packetCount + 1) >>> 0;
    this.#octetCount = (this.#octetCount + opusBytes.length) >>> 0;
    if (sequenceNumber === 0xffff) {
      this.#sequenceNumber = 0;
      this.#roc = (this.#roc + 1) >>> 0;
    } else {
      this.#sequenceNumber = (sequenceNumber + 1) & 0xffff;
    }
    const sampleStep =
      explicitSampleStep !== undefined && explicitSampleStep > 0
        ? Math.floor(explicitSampleStep)
        : this.samplesPerFrame * stepFrames;
    this.#timestamp = (timestamp + sampleStep) >>> 0;

    if (this.#traceEnabled) {
      traceRelayPacket("send", protectedPacket, "rtp", {
        ssrc: this.ssrc,
        sequenceNumber,
        payloadType: this.payloadType,
        rocAfter: this.#roc,
        selfDecryptOk,
        selfDecryptError,
      });
    }
    {
      const hasExt = (packet[0]! & 0x10) !== 0;
      const extProfile = hasExt ? readUint16BE(packet, 12) : 0;
      const tagLen = protectedPacket.length - packet.length;
      diagTx({
        seq: sequenceNumber,
        ssrc: this.ssrc,
        roc: this.#roc,
        extProfile,
        payloadLen: opusBytes.length,
        miTag: tagLen > 0 ? protectedPacket.slice(protectedPacket.length - tagLen) : new Uint8Array(0),
        full: protectedPacket,
        opusToc: opusBytes.length > 0 ? opusBytes[0]! : -1,
      });
    }
    return protectedPacket;
  }

  packetizeRtcpSr(): Uint8Array {
    const ntp = buildNtpTimestamp();
    const sr = buildRtcpSenderReport({
      ssrc: this.ssrc,
      ntpMost: ntp.most,
      ntpLeast: ntp.least,
      rtpTimestamp: this.#timestamp,
      packetCount: this.#packetCount,
      octetCount: this.#octetCount,
    });
    const index = this.#nextRtcpIndex();
    const protectedPacket = this.#srtp.protectRtcp(sr, index);
    if (this.#traceEnabled) {
      traceRelayPacket("send", protectedPacket, "rtcp", {
        ssrc: this.ssrc,
        rtcpIndex: index,
      });
    }
    return protectedPacket;
  }

  packetizeRtcpSdes(): Uint8Array | null {
    if (!this.#cname) return null;
    const sdes = buildRtcpSourceDescription({
      ssrc: this.ssrc,
      cname: this.#cname,
    });
    const index = this.#nextRtcpIndex();
    const protectedPacket = this.#srtp.protectRtcp(sdes, index);
    if (this.#traceEnabled) {
      traceRelayPacket("send", protectedPacket, "rtcp", {
        ssrc: this.ssrc,
        rtcpIndex: index,
      });
    }
    return protectedPacket;
  }

  packetizeWarpTransportFeedback(rtpIndex?: number): Uint8Array {
    const idx = rtpIndex ?? (((this.#roc << 16) | this.#sequenceNumber) >>> 0);
    const tfb = buildWarpTransportFeedback({ ssrc: this.ssrc, rtpIndex: idx });
    const index = this.#nextRtcpIndex();
    const protectedPacket = this.#srtp.protectRtcp(tfb, index);
    if (this.#traceEnabled) {
      traceRelayPacket("send", protectedPacket, "rtcp", {
        ssrc: this.ssrc,
        rtcpIndex: index,
      });
    }
    return protectedPacket;
  }

  packetizeWarpStreamHello(): Uint8Array {
    const hello = buildWarpStreamHello({ ssrc: this.ssrc });
    const index = this.#nextRtcpIndex();
    const protectedPacket = this.#srtp.protectRtcp(hello, index);
    if (this.#traceEnabled) {
      traceRelayPacket("send", protectedPacket, "rtcp", {
        ssrc: this.ssrc,
        rtcpIndex: index,
      });
    }
    return protectedPacket;
  }

  packetizeWarpApplicationFeedback(appData?: Uint8Array): Uint8Array {
    const afb = buildWarpApplicationFeedback({
      ssrc: this.ssrc,
      mediaSsrc: this.ssrc,
      appData,
    });
    const index = this.#nextRtcpIndex();
    const protectedPacket = this.#srtp.protectRtcp(afb, index);
    if (this.#traceEnabled) {
      traceRelayPacket("send", protectedPacket, "rtcp", {
        ssrc: this.ssrc,
        rtcpIndex: index,
      });
    }
    return protectedPacket;
  }

  #nextRtcpIndex(): number {
    const next = this.#rtcpIndex >>> 0;
    this.#rtcpIndex = (this.#rtcpIndex + 1) >>> 0;
    return next;
  }

  getStats(): {
    sequenceNumber: number;
    timestamp: number;
    roc: number;
    packetCount: number;
    octetCount: number;
    rtcpIndex: number;
  } {
    return {
      sequenceNumber: this.#sequenceNumber,
      timestamp: this.#timestamp,
      roc: this.#roc,
      packetCount: this.#packetCount,
      octetCount: this.#octetCount,
      rtcpIndex: this.#rtcpIndex,
    };
  }
}

interface PerSsrcRecvState {
  roc: number;
  /** Highest sequence number observed in the current ROC window. */
  highestSeq: number;
  /** Number of packets delivered through the engine. */
  packetsReceived: number;
  /** Total octets delivered (post-decrypt). */
  octetsReceived: number;
}

const newRecvState = (): PerSsrcRecvState => ({
  roc: 0,
  highestSeq: 0,
  packetsReceived: 0,
  octetsReceived: 0,
});

const ROC_WINDOW_HALF = 0x8000;

/**
 * RTP receive engine. Tracks ROC per SSRC using the canonical RFC 3711
 * "shifted highest sequence number" rule: a packet whose sequence number
 * sits more than half the 16-bit space below the previously highest
 * sequence number is treated as belonging to the next ROC window, and a
 * packet whose sequence number sits more than half above is treated as a
 * straggler from the previous window.
 */
export class RtpRecvEngine {
  #srtp: SrtpContext;
  #states = new Map<number, PerSsrcRecvState>();
  #rtcpUnprotectCount = 0;
  #traceEnabled: boolean;
  #expectedSsrcs: Set<number> | null;

  constructor(
    srtp: SrtpContext,
    options: { trace?: boolean; expectedSsrcs?: number[] } = {},
  ) {
    this.#srtp = srtp;
    this.#traceEnabled = options.trace !== false;
    this.#expectedSsrcs =
      options.expectedSsrcs && options.expectedSsrcs.length > 0
        ? new Set(options.expectedSsrcs.map((s) => s >>> 0))
        : null;
  }

  setContext(srtp: SrtpContext, expectedSsrcs?: number[]): void {
    this.#srtp = srtp;
    if (expectedSsrcs && expectedSsrcs.length > 0) {
      this.#expectedSsrcs = new Set(expectedSsrcs.map((s) => s >>> 0));
    }
  }

  unprotectRtp(packet: Uint8Array): Uint8Array {
    if (packet.length < 12) throw new Error("RTP packet too short for SRTP unprotect");
    const sequenceNumber = readUint16BE(packet, 2);
    const ssrc = readUint32BE(packet, 8) >>> 0;
    const state = this.#states.get(ssrc) ?? newRecvState();
    const rocForPacket = this.#computeRocForPacket(state, sequenceNumber);

    const miOk = this.#srtp.verifyRtpAuthTag(packet, rocForPacket);
    const ssrcExpected = this.#expectedSsrcs ? this.#expectedSsrcs.has(ssrc) : null;

    let cleartext: Uint8Array;
    try {
      cleartext = this.#srtp.unprotectRtp(packet, rocForPacket);
    } catch (error) {
      diagRx({
        ssrc, seq: sequenceNumber, roc: rocForPacket, len: packet.length,
        miOk, ssrcExpected, decryptOk: false, error: String(error),
      });
      throw error;
    }

    this.#commitRoc(state, sequenceNumber, rocForPacket);
    state.packetsReceived = (state.packetsReceived + 1) >>> 0;
    const parsed = parseRtp(cleartext);
    state.octetsReceived = (state.octetsReceived + parsed.payload.length) >>> 0;
    this.#states.set(ssrc, state);

    diagRx({
      ssrc, seq: sequenceNumber, roc: rocForPacket, len: packet.length,
      miOk, ssrcExpected, decryptOk: true,
      opusTocHex: Buffer.from(
        parsed.payload.buffer,
        parsed.payload.byteOffset,
        Math.min(parsed.payload.length, 2),
      ).toString("hex"),
    });

    if (this.#traceEnabled) {
      traceRelayPacket("recv", cleartext, "rtp", {
        ssrc, sequenceNumber, payloadType: parsed.payloadType,
        rocAfter: state.roc, decryptOk: true,
      });
      traceMediaPacket("recv_cleartext", cleartext, {
        ssrc, sequenceNumber, payloadType: parsed.payloadType,
        payloadLength: parsed.payload.length, opusToc: parsed.payload[0] ?? null,
      });
    }
    return cleartext;
  }

  unprotectRtcp(packet: Uint8Array): { packet: Uint8Array; index: number } {
    const result = this.#srtp.unprotectRtcp(packet);
    this.#rtcpUnprotectCount = (this.#rtcpUnprotectCount + 1) >>> 0;
    if (this.#traceEnabled) {
      traceRelayPacket("recv", result.packet, "rtcp", {
        rtcpIndex: result.index, decryptOk: true,
      });
    }
    return result;
  }

  getStats(ssrc?: number): {
    packetsReceived: number;
    octetsReceived: number;
    rtcpUnprotectCount: number;
    bySsrc: Array<{
      ssrc: number; roc: number; highestSeq: number;
      packetsReceived: number; octetsReceived: number;
    }>;
  } {
    const bySsrc: Array<{
      ssrc: number; roc: number; highestSeq: number;
      packetsReceived: number; octetsReceived: number;
    }> = [];
    let packetsReceived = 0;
    let octetsReceived = 0;
    for (const [key, state] of this.#states.entries()) {
      packetsReceived += state.packetsReceived;
      octetsReceived += state.octetsReceived;
      if (ssrc === undefined || key === ssrc) {
        bySsrc.push({
          ssrc: key, roc: state.roc, highestSeq: state.highestSeq,
          packetsReceived: state.packetsReceived, octetsReceived: state.octetsReceived,
        });
      }
    }
    return { packetsReceived, octetsReceived, rtcpUnprotectCount: this.#rtcpUnprotectCount, bySsrc };
  }

  #computeRocForPacket(state: PerSsrcRecvState, sequenceNumber: number): number {
    if (state.packetsReceived === 0) return state.roc;
    const high = state.highestSeq;
    if (high < ROC_WINDOW_HALF) {
      if (sequenceNumber - high > ROC_WINDOW_HALF && state.roc > 0) return (state.roc - 1) >>> 0;
      return state.roc;
    }
    if (high - sequenceNumber > ROC_WINDOW_HALF) return (state.roc + 1) >>> 0;
    return state.roc;
  }

  #commitRoc(state: PerSsrcRecvState, sequenceNumber: number, rocForPacket: number): void {
    if (state.packetsReceived === 0) {
      state.highestSeq = sequenceNumber;
      state.roc = rocForPacket;
      return;
    }
    const currentExtended = state.roc * 0x10000 + state.highestSeq;
    const incomingExtended = rocForPacket * 0x10000 + sequenceNumber;
    if (incomingExtended > currentExtended) {
      state.highestSeq = sequenceNumber;
      state.roc = rocForPacket;
    }
  }
}
