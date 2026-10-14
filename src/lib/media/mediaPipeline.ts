/**
 * ============================================================================
 * STACK LAYER 6 — Media orchestration
 * ============================================================================
 *
 * Wires the MLow WASM encoder to the RTP/SRTP pipeline. Strips the encoder's
 * dummy RTP header back to the bare codec payload, paces one frame per 60 ms
 * on a drift-corrected monotonic clock, drives rtpEngine + SRTP, sends to every
 * relay target, and runs the WARP RTCP control cadence. The receive side
 * unprotects, tracks ROC, decodes, and emits PCM.
 */
import * as nodeFs from "node:fs";
import {
  classifyPacket,
  parseDatagram,
  type DatagramInfo,
} from "../protocol/protocol";
import {
  FfmpegOpusRtpReceiver,
  type FfmpegRtpPacket,
} from "./ffmpegRtp";
import { MlowWasmRtpSender, MLOW_WASM_RTP_TIMESTAMP_STEP_48K } from "./mlowWasmRtp";
import { RtpRecvEngine, RtpSendEngine } from "./rtpEngine";
import { SrtpContext } from "../crypto/srtp";
import { traceAudioPcm, traceMediaPacket, traceRelayPacket } from "../app/trace";

export interface MediaPipelineSendTarget {
  ip: string;
  port: number;
}

export interface MediaPipelineOptions {
  source: string;
  targets: MediaPipelineSendTarget[];
  uplink: SrtpContext;
  downlink?: SrtpContext;
  senderSsrc: number;
  expectedPeerSsrcs?: number[];
  payloadType?: number;
  sampleRate?: number;
  channels?: number;
  bitrateBps?: number;
  audioFilter?: string;
  ffmpegPath?: string;
  send: (packet: Uint8Array, ip: string, port: number) => unknown;
  onAudioPlaybackData?: (samples: Float32Array) => void;
  initialSequenceNumber?: number;
  initialTimestamp?: number;
  trace?: boolean;
  audioPiggyback?: boolean;
  sendEveryNFrames?: number;
}

export interface MediaPipelineStats {
  rtpSent: number;
  rtpReceived: number;
  rtcpSent: number;
  rtcpReceived: number;
  octetsSent: number;
  octetsReceived: number;
  stunDatagrams: number;
  unclassifiedDatagrams: number;
}

const cloneStats = (stats: MediaPipelineStats): MediaPipelineStats => ({
  rtpSent: stats.rtpSent,
  rtpReceived: stats.rtpReceived,
  rtcpSent: stats.rtcpSent,
  rtcpReceived: stats.rtcpReceived,
  octetsSent: stats.octetsSent,
  octetsReceived: stats.octetsReceived,
  stunDatagrams: stats.stunDatagrams,
  unclassifiedDatagrams: stats.unclassifiedDatagrams,
});

export class MediaPipeline {
  readonly options: MediaPipelineOptions;
  readonly sender: MlowWasmRtpSender;
  readonly receiver: FfmpegOpusRtpReceiver;
  readonly rtpSendEngine: RtpSendEngine;
  readonly rtpRecvEngine: RtpRecvEngine;
  #started = false;
  #stopped = false;
  #stats: MediaPipelineStats = {
    rtpSent: 0, rtpReceived: 0, rtcpSent: 0, rtcpReceived: 0,
    octetsSent: 0, octetsReceived: 0, stunDatagrams: 0, unclassifiedDatagrams: 0,
  };
  #traceEnabled: boolean;
  #warpRtpSendCount = 0;
  #warpStreamHelloSent = false;
  static readonly WARP_TFB_EVERY = 8;
  static readonly WARP_AFB_EVERY = 25;

  #opusQueue: Uint8Array[] = [];
  #paceIntervalMs = 60;
  #fixedTimestampStep = MLOW_WASM_RTP_TIMESTAMP_STEP_48K;
  #nextSendAt = 0;
  #paceTimer: ReturnType<typeof setTimeout> | null = null;
  static readonly PACE_PREBUFFER_FRAMES = 1;
  static readonly PACE_MAX_QUEUE_FRAMES = 10000;
  #pacerStarted = false;
  #sendEveryNFrames: number;
  #skippedFrameCount = 0;

  constructor(options: MediaPipelineOptions) {
    if (options.targets.length === 0) throw new Error("MediaPipeline needs at least one relay target");
    this.options = options;
    this.#traceEnabled = options.trace !== false;
    this.#sendEveryNFrames = Math.max(1, Math.floor(options.sendEveryNFrames ?? 1));
    const frameDurationMs = 60;
    this.#paceIntervalMs = frameDurationMs;
    this.rtpSendEngine = new RtpSendEngine(options.uplink, {
      ssrc: options.senderSsrc,
      payloadType: options.payloadType,
      sampleRate: options.sampleRate,
      frameDurationMs,
      initialSequenceNumber: options.initialSequenceNumber,
      initialTimestamp: options.initialTimestamp,
      audioPiggyback: options.audioPiggyback ?? false,
      trace: this.#traceEnabled,
    });
    this.rtpRecvEngine = new RtpRecvEngine(options.downlink ?? options.uplink, {
      trace: this.#traceEnabled,
      expectedSsrcs: options.expectedPeerSsrcs,
    });

    this.receiver = new FfmpegOpusRtpReceiver({
      ffmpegPath: options.ffmpegPath,
      payloadType: options.payloadType,
      sampleRate: options.sampleRate,
      channels: options.channels,
      onSamples: (samples) => {
        if (this.#traceEnabled) {
          traceAudioPcm("rx", samples, {
            sampleRate: options.sampleRate,
            channels: options.channels,
            framesPerChunk: samples.length,
          });
        }
        try { options.onAudioPlaybackData?.(samples); } catch {}
      },
    });

    this.sender = new MlowWasmRtpSender({
      source: options.source,
      ffmpegPath: options.ffmpegPath,
      payloadType: options.payloadType,
      bitrateBps: options.bitrateBps ?? 25000,
      ssrc: options.senderSsrc,
      audioFilter: options.audioFilter,
      onPacket: (packet) => this.#handleOutgoing(packet),
    });
  }

  async start(): Promise<void> {
    if (this.#started) return;
    if (this.#stopped) throw new Error("MediaPipeline already stopped");
    this.#started = true;
    await this.receiver.start();

    const replayPath = process.env.CALL_REPLAY_OPUS_PATH;
    if (replayPath) {
      this.#startReplay(replayPath);
      return;
    }

    await this.sender.start();
  }

  #startReplay(path: string): void {
    const lines: string[] = nodeFs.readFileSync(path, "utf8").split("\n").filter((l: string) => l.trim());
    const frames: Uint8Array[] = [];
    for (const l of lines) {
      try {
        const d = JSON.parse(l);
        if (typeof d.hex === "string" && d.hex.length >= 2) {
          frames.push(Uint8Array.from(Buffer.from(d.hex, "hex")));
        }
      } catch {}
    }
    if (frames.length === 0) {
      console.error(`[replay] no frames loaded from ${path}`);
      return;
    }
    console.error(`[replay] loaded ${frames.length} Opus frames from ${path}; feeding at ${this.#paceIntervalMs}ms`);
    let i = 0;
    const loop = Boolean(Number(process.env.CALL_REPLAY_LOOP ?? "1"));
    const feed = (): void => {
      if (this.#stopped || !this.#started) return;
      if (i >= frames.length) {
        if (!loop) return;
        i = 0;
      }
      const f = frames[i++]!;
      if (this.#opusQueue.length >= MediaPipeline.PACE_MAX_QUEUE_FRAMES) {
        this.#opusQueue.shift();
      }
      this.#opusQueue.push(f);
      this.#maybeStartPacer();
      setTimeout(feed, this.#paceIntervalMs);
    };
    feed();
  }

  stop(): void {
    if (this.#stopped) return;
    this.#stopped = true;
    this.#started = false;
    if (this.#paceTimer !== null) {
      clearTimeout(this.#paceTimer);
      this.#paceTimer = null;
    }
    this.#opusQueue.length = 0;
    try { this.sender.stop(); } catch {}
    try { this.receiver.stop(); } catch {}
  }

  getStats(): MediaPipelineStats {
    return cloneStats(this.#stats);
  }

  setDownlink(downlink: SrtpContext, expectedPeerSsrcs?: number[]): void {
    this.rtpRecvEngine.setContext(downlink, expectedPeerSsrcs);
  }

  feedDatagram(packet: Uint8Array, host = "", port = 0): DatagramInfo {
    const info = parseDatagram(packet, host, port);
    switch (info.kind) {
      case "rtp": this.#handleIncomingRtp(packet); break;
      case "rtcp": this.#handleIncomingRtcp(packet); break;
      case "stun": this.#stats.stunDatagrams += 1; break;
      default: this.#stats.unclassifiedDatagrams += 1; break;
    }
    return info;
  }

  #handleIncomingRtp(packet: Uint8Array): void {
    let cleartext: Uint8Array;
    try {
      cleartext = this.rtpRecvEngine.unprotectRtp(packet);
    } catch (error) {
      if (this.#traceEnabled) {
        traceRelayPacket("recv", packet, "rtp", { decryptOk: false, decryptError: String(error) });
      }
      return;
    }
    this.#stats.rtpReceived += 1;
    this.#stats.octetsReceived += cleartext.length;
    void this.receiver.feedRtp(cleartext).catch(() => {});
  }

  #handleIncomingRtcp(packet: Uint8Array): void {
    let result: { packet: Uint8Array; index: number };
    try {
      result = this.rtpRecvEngine.unprotectRtcp(packet);
    } catch (error) {
      if (this.#traceEnabled) {
        traceRelayPacket("recv", packet, "rtcp", { decryptOk: false, decryptError: String(error) });
      }
      return;
    }
    this.#stats.rtcpReceived += 1;
    void this.receiver.feedRtcp(result.packet).catch(() => {});
  }

  #handleOutgoing(packet: FfmpegRtpPacket): void {
    if (!this.#started) return;
    if (packet.kind === "rtp") {
      this.#enqueueOutgoingRtp(packet.packet);
      return;
    }
    if (packet.kind === "rtcp") {
      this.#sendRtcp(packet.packet);
    }
  }

  #enqueueOutgoingRtp(rawRtpPacket: Uint8Array): void {
    const headerLength = 12;
    if (rawRtpPacket.length < headerLength) return;
    const payloadOffset = computePayloadOffset(rawRtpPacket);
    if (payloadOffset === null) return;
    const opusBytes = rawRtpPacket.slice(payloadOffset);
    traceMediaPacket("ffmpeg_rtp", rawRtpPacket, { payloadOffset, payloadLength: opusBytes.length, opusToc: opusBytes[0] ?? null });
    traceMediaPacket("opus_payload", opusBytes, { source: "ffmpeg", opusToc: opusBytes[0] ?? null });
    if (this.#opusQueue.length >= MediaPipeline.PACE_MAX_QUEUE_FRAMES) {
      this.#opusQueue.shift();
    }
    this.#opusQueue.push(opusBytes);
    this.#maybeStartPacer();
  }

  #maybeStartPacer(): void {
    if (this.#pacerStarted) return;
    if (this.#opusQueue.length < MediaPipeline.PACE_PREBUFFER_FRAMES) return;
    this.#pacerStarted = true;
    this.#nextSendAt = nowMs();
    this.#drainPaced();
  }

  #drainPaced(): void {
    if (this.#stopped || !this.#started) return;
    const frame = this.#opusQueue.shift();
    if (this.#traceEnabled) {
      traceMediaPacket("pacer_tick", new Uint8Array(0), {
        queueDepthAfterPop: this.#opusQueue.length,
        hadFrame: frame !== undefined,
        paceIntervalMs: this.#paceIntervalMs,
      });
    }
    if (frame !== undefined) {
      if (this.#sendEveryNFrames > 1 && (this.#warpRtpSendCount + this.#skippedFrameCount) % this.#sendEveryNFrames !== 0) {
        this.#skippedFrameCount += 1;
      } else {
        const timestampStepFrames = 1 + this.#skippedFrameCount;
        this.#skippedFrameCount = 0;
        this.#sendRtp(frame, timestampStepFrames);
      }
    }
    this.#nextSendAt += this.#paceIntervalMs;
    const delay = Math.max(0, this.#nextSendAt - nowMs());
    this.#paceTimer = setTimeout(() => this.#drainPaced(), delay);
  }

  setTargets(targets: MediaPipelineSendTarget[]): void {
    if (targets.length === 0) return;
    this.options.targets = targets;
  }

  #sendToTargets(packet: Uint8Array): void {
    for (const target of this.options.targets) {
      try { this.options.send(packet, target.ip, target.port); } catch {}
    }
  }

  #sendRtp(opusBytes: Uint8Array, timestampStepFrames = 1): void {
    if (this.#warpRtpSendCount === 0) {
      this.#sendRtcpSdesOnly();
    }

    const explicitSampleStep = this.#fixedTimestampStep > 0
      ? this.#fixedTimestampStep * timestampStepFrames
      : undefined;
    const protectedPacket = this.rtpSendEngine.packetize(opusBytes, timestampStepFrames, explicitSampleStep);

    if (process.env.CALL_DUMP_OPUS_FRAMES_PATH) {
      try {
        nodeFs.appendFileSync(
          process.env.CALL_DUMP_OPUS_FRAMES_PATH,
          JSON.stringify({
            ts: Date.now(),
            seq: (protectedPacket && protectedPacket.length >= 4)
              ? ((protectedPacket[2] << 8) | protectedPacket[3]) : null,
            len: opusBytes.length,
            hex: Buffer.from(opusBytes).toString("hex"),
          }) + "\n",
        );
      } catch {}
    }
    this.#stats.rtpSent += 1;
    this.#stats.octetsSent += opusBytes.length;
    this.#sendToTargets(protectedPacket);
    this.#warpRtpSendCount += 1;

    if (this.#warpRtpSendCount === 1 || this.#warpRtpSendCount % MediaPipeline.WARP_TFB_EVERY === 0) {
      this.#sendToTargets(this.rtpSendEngine.packetizeWarpTransportFeedback());
      this.#stats.rtcpSent += 1;
    }
    if (!this.#warpStreamHelloSent && this.#warpRtpSendCount === 4) {
      this.#sendToTargets(this.rtpSendEngine.packetizeWarpStreamHello());
      this.#stats.rtcpSent += 1;
      this.#warpStreamHelloSent = true;
    }
    if (this.#warpRtpSendCount % MediaPipeline.WARP_AFB_EVERY === 0) {
      this.#sendToTargets(this.rtpSendEngine.packetizeWarpApplicationFeedback());
      this.#stats.rtcpSent += 1;
    }
  }

  #sendRtcpSdesOnly(): void {
    const protectedSdes = this.rtpSendEngine.packetizeRtcpSdes();
    if (protectedSdes) {
      this.#stats.rtcpSent += 1;
      this.#sendToTargets(protectedSdes);
    }
  }

  #sendRtcp(_rawRtcpPacket: Uint8Array): void {
    const protectedSr = this.rtpSendEngine.packetizeRtcpSr();
    this.#stats.rtcpSent += 1;
    this.#sendToTargets(protectedSr);

    const protectedSdes = this.rtpSendEngine.packetizeRtcpSdes();
    if (protectedSdes) {
      this.#stats.rtcpSent += 1;
      this.#sendToTargets(protectedSdes);
    }
  }
}

const nowMs = (): number => Number(process.hrtime.bigint()) / 1e6;

const computePayloadOffset = (packet: Uint8Array): number | null => {
  if (packet.length < 12) return null;
  const cc = packet[0]! & 0x0f;
  const hasExtension = (packet[0]! & 0x10) !== 0;
  let offset = 12 + cc * 4;
  if (offset > packet.length) return null;
  if (hasExtension) {
    if (offset + 4 > packet.length) return null;
    const extensionWords = (packet[offset + 2]! << 8) | packet[offset + 3]!;
    offset += 4 + extensionWords * 4;
  }
  if (offset > packet.length) return null;
  return offset;
};

export { classifyPacket };
