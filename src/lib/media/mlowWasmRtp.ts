/**
 * ============================================================================
 * STACK LAYER 5 — Audio codec (MLow, WASM)
 * ============================================================================
 *
 * Encodes with WhatsApp's proprietary MLow codec via the libopus_mlow-wasm
 * module (useSmpl=true), producing genuine MLow packets (CTL 4050) at a
 * constant 60 ms / 960-sample frame.
 *
 * Flow:
 *   1) Decode source audio to 16 kHz mono float PCM with ffmpeg.
 *   2) Encode the entire source into MLow frames in memory.
 *   3) Push those frames out one at a time at 60 ms intervals.
 *
 * Why this shape:
 *   - It matches the Docker backend's real-time pacing behavior.
 *   - It avoids bursty delivery, which can make playback drift or sound slow.
 *   - The downstream pipeline only needs bare MLow payloads plus a dummy RTP
 *     header; mediaPipeline / rtpEngine can re-frame them later.
 */
import { spawn } from "node:child_process";
import {
  createEncoder,
  opusGlobalCreate,
  Application,
  type OpusEncoderHandle,
} from "../../vendor/libopus-wasm/index";

export interface MlowWasmSenderOptions {
  source: string;
  payloadType?: number;
  ssrc?: number;
  bitrateBps?: number;
  audioFilter?: string;
  onPacket: (packet: { kind: "rtp" | "rtcp"; packet: Uint8Array }) => void;
  ffmpegPath?: string;
}

const MLOW_FRAME_MS = 60;
const MLOW_SAMPLES_PER_FRAME = (16000 * MLOW_FRAME_MS) / 1000; // 960 samples @ 16 kHz
const MLOW_TIMESTAMP_STEP_48K = (48000 * MLOW_FRAME_MS) / 1000; // 2880 @ 48 kHz RTP clock

export class MlowWasmRtpSender {
  #ffmpegPath: string;
  #payloadType: number;
  #ssrc: number;
  #bitrateBps: number;
  #audioFilter: string;
  #onPacket: (packet: { kind: "rtp" | "rtcp"; packet: Uint8Array }) => void;
  #source: string;

  #encoder: OpusEncoderHandle | null = null;
  #started = false;

  #seq = 0;
  #timestamp = 0;

  #frames: Uint8Array[] = [];
  #frameIndex = 0;
  #feedTimer: ReturnType<typeof setInterval> | null = null;

  constructor(options: MlowWasmSenderOptions) {
    this.#ffmpegPath = options.ffmpegPath || "ffmpeg";
    this.#payloadType = options.payloadType ?? 120;
    this.#ssrc = options.ssrc ?? ((Math.random() * 0xffffffff) >>> 0);
    this.#bitrateBps = options.bitrateBps ?? 25000;
    this.#audioFilter = options.audioFilter ?? "aresample=resampler=swr:cutoff=0.99";
    this.#onPacket = options.onPacket;
    this.#source = options.source;
  }

  async start(): Promise<void> {
    if (this.#started) return;
    this.#started = true;

    await opusGlobalCreate();

    this.#encoder = await createEncoder({
      sampleRate: 16000,
      channels: 1,
      application: Application.Voip,
      bitrate: this.#bitrateBps,
      complexity: 9,
      frameSize: MLOW_SAMPLES_PER_FRAME,
      useSmpl: true,
      dtx: true,
    });

    const pcmBuf = await this.#decodeToPcm();

    this.#frames = this.#encodeAllFrames(pcmBuf);
    if (this.#frames.length === 0) {
      throw new Error("MLow WASM encoder produced no frames");
    }

    this.#frameIndex = 0;

    this.#feedTimer = setInterval(() => this.#emitNextFrame(), MLOW_FRAME_MS);
    this.#emitNextFrame();
  }

  #encodeAllFrames(pcmBuf: Buffer): Uint8Array[] {
    const encodedFrames: Uint8Array[] = [];
    const frameBytes = MLOW_SAMPLES_PER_FRAME * 4;
    let offset = 0;

    while (offset + frameBytes <= pcmBuf.length) {
      const floats = new Float32Array(
        pcmBuf.buffer,
        pcmBuf.byteOffset + offset,
        MLOW_SAMPLES_PER_FRAME,
      );
      offset += frameBytes;

      try {
        const mlow = this.#encoder?.encodeFloat(floats);
        if (!mlow || mlow.length === 0) continue;
        encodedFrames.push(mlow);
      } catch {
        // Skip bad frames rather than failing the entire stream.
      }
    }

    return encodedFrames;
  }

  #emitNextFrame(): void {
    if (!this.#started || this.#frames.length === 0) return;

    const mlow = this.#frames[this.#frameIndex]!;
    this.#frameIndex = (this.#frameIndex + 1) % this.#frames.length;

    const pkt = new Uint8Array(12 + mlow.length);

    pkt[0] = 0x80;
    pkt[1] = this.#payloadType & 0x7f;

    pkt[2] = (this.#seq >> 8) & 0xff;
    pkt[3] = this.#seq & 0xff;

    pkt[4] = (this.#timestamp >>> 24) & 0xff;
    pkt[5] = (this.#timestamp >>> 16) & 0xff;
    pkt[6] = (this.#timestamp >>> 8) & 0xff;
    pkt[7] = this.#timestamp & 0xff;

    pkt[8] = (this.#ssrc >>> 24) & 0xff;
    pkt[9] = (this.#ssrc >>> 16) & 0xff;
    pkt[10] = (this.#ssrc >>> 8) & 0xff;
    pkt[11] = this.#ssrc & 0xff;

    pkt.set(mlow, 12);

    this.#seq = (this.#seq + 1) & 0xffff;
    this.#timestamp = (this.#timestamp + MLOW_TIMESTAMP_STEP_48K) >>> 0;

    this.#onPacket({ kind: "rtp", packet: pkt });
  }

  #decodeToPcm(): Promise<Buffer> {
    const inputArgs = this.#source.startsWith("lavfi:")
      ? ["-f", "lavfi", "-i", this.#source.slice("lavfi:".length)]
      : ["-i", this.#source];

    const args = [
      "-hide_banner",
      "-loglevel",
      "error",
      ...inputArgs,
      "-vn",
      "-map",
      "0:a:0",
      ...(this.#audioFilter ? ["-af", this.#audioFilter] : []),
      "-ac",
      "1",
      "-ar",
      "16000",
      "-af",
      "atempo=1.17",
      "-f",
      "f32le",
      "pipe:1",
    ];

    return new Promise<Buffer>((resolve, reject) => {
      const child = spawn(this.#ffmpegPath, args, {
        stdio: ["ignore", "pipe", "pipe"],
      });

      const chunks: Buffer[] = [];
      let stderr = "";

      child.stdout?.on("data", (d: Buffer) => chunks.push(d));
      child.stderr?.on("data", (d: Buffer) => {
        stderr += d.toString();
      });

      child.once("exit", (code) => {
        if (code === 0) {
          resolve(Buffer.concat(chunks));
        } else {
          reject(new Error(`ffmpeg exit ${code}: ${stderr.slice(-200)}`));
        }
      });

      child.once("error", reject);
    });
  }

  stop(): void {
    if (this.#feedTimer !== null) {
      clearInterval(this.#feedTimer);
      this.#feedTimer = null;
    }

    if (this.#encoder) {
      try { this.#encoder.free(); } catch {}
      this.#encoder = null;
    }

    this.#frames = [];
    this.#frameIndex = 0;
    this.#started = false;
  }
}

export const MLOW_WASM_RTP_TIMESTAMP_STEP_48K = MLOW_TIMESTAMP_STEP_48K;