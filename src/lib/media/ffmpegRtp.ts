/**
 * ============================================================================
 * STACK LAYER 5b — Inbound audio decoder
 * ============================================================================
 *
 * Receives cleartext Opus RTP packets (already SRTP-decrypted by the engine),
 * feeds them into an ffmpeg child process over loopback UDP, and emits decoded
 * Float32 PCM samples. This is the RECEIVE side of the audio path — the send
 * side is mlowWasmRtp.ts.
 *
 * Why ffmpeg for decode: ffmpeg's libopus decoder handles every legitimate
 * Opus frame configuration (SILK/CELT/hybrid, any bandwidth, FEC, DTX)
 * correctly, even unusual WhatsApp MLow frames that look like standard Opus
 * but carry extended frame counts. A pure-WASM decoder can't reliably decode
 * the variety of inbound frames from peer devices.
 *
 * Why loopback UDP instead of a direct pipe: ffmpeg's RTP-multiplexer path
 * tracks sequence numbers and timestamps across dropped/duplicated/reordered
 * packets, producing smooth output rather than glitchy PCM with gaps.
 */
import dgram from "node:dgram";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, type ChildProcess } from "node:child_process";

export interface FfmpegRtpPacket {
  kind: "rtcp" | "rtp";
  packet: Uint8Array;
}

export interface FfmpegOpusReceiverOptions {
  payloadType?: number;
  sampleRate?: number;
  channels?: number;
  ffmpegPath?: string;
  onSamples?: (chunk: Float32Array) => void;
}

/**
 * Reserve an available UDP port on loopback. The port is released immediately
 * after the call; we only need the number so ffmpeg can bind it.
 *
 * Needed because ffmpeg must open the RTP/RTCP ports itself, so we can't
 * pass an fd — we have to tell it a port number.
 */
const reserveUdpPort = async () => {
  const socket = dgram.createSocket("udp4");
  const port = await new Promise<number>((resolve, reject) => {
    socket.once("error", reject);
    socket.once("listening", () => {
      const address = socket.address();
      if (typeof address === "string") { reject(new Error("unexpected")); return; }
      resolve(address.port);
    });
    socket.bind(0, "127.0.0.1");
  });
  socket.close();
  return port;
};

const killChild = (child: ChildProcess | null) => {
  if (!child) return;
  try { child.kill("SIGTERM"); } catch {}
};

/**
 * Receives Opus RTP packets and decodes them to PCM via an ffmpeg child.
 *
 * Architecture: cleartext RTP → loopback UDP socket → ffmpeg (libopus) →
 * float32 PCM stdout → onSamples callback. The loopback hop is intentional —
 * it lets ffmpeg's RTP depacketizer handle jitter, reordering, and lost
 * packets so we get smooth output without implementing a full jitter buffer
 * in JS.
 */
export class FfmpegOpusRtpReceiver {
  #ffmpegPath: string;
  #payloadType: number;
  #sampleRate: number;
  #channels: number;
  #onSamples?: (chunk: Float32Array) => void;
  #child: ChildProcess | null = null;
  #injectSocket: dgram.Socket | null = null;
  #started = false;
  #pcmPending = Buffer.alloc(0);
  #tempDir: string | null = null;
  #sdpPath: string | null = null;
  public rtpPort = 0;
  public rtcpPort = 0;

  constructor(options: FfmpegOpusReceiverOptions = {}) {
    this.#ffmpegPath = options.ffmpegPath || "ffmpeg";
    this.#payloadType = options.payloadType ?? 120;
    this.#sampleRate = options.sampleRate ?? 48000;
    this.#channels = options.channels ?? 1;
    this.#onSamples = options.onSamples;
  }

  async start(): Promise<void> {
    if (this.#started) return;
    this.#started = true;
    this.rtpPort = await reserveUdpPort();
    this.rtcpPort = await reserveUdpPort();
    this.#injectSocket = dgram.createSocket("udp4");
    this.#tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "node-load-rtp-"));
    this.#sdpPath = path.join(this.#tempDir, "audio.sdp");
    const sdp = [
      "v=0",
      "o=- 0 0 IN IP4 127.0.0.1",
      "s=node-load-opus",
      "c=IN IP4 127.0.0.1",
      "t=0 0",
      `m=audio ${this.rtpPort} RTP/AVP ${this.#payloadType}`,
      `a=rtcp:${this.rtcpPort}`,
      `a=rtpmap:${this.#payloadType} opus/${this.#sampleRate}/${this.#channels}`,
      "a=recvonly",
      "",
    ].join("\n");
    fs.writeFileSync(this.#sdpPath, sdp);

    const child = spawn(
      this.#ffmpegPath,
      [
        "-hide_banner", "-loglevel", "error",
        "-protocol_whitelist", "file,udp,rtp",
        "-fflags", "nobuffer",
        "-i", this.#sdpPath,
        "-f", "f32le",
        "-ac", String(this.#channels),
        "-ar", String(this.#sampleRate),
        "pipe:1",
      ],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    this.#child = child;

    child.stdout?.on("data", (chunk: Buffer) => {
      this.#pcmPending = Buffer.concat([this.#pcmPending, chunk]);
      const frameBytes = Float32Array.BYTES_PER_ELEMENT;
      const usableBytes = this.#pcmPending.length - (this.#pcmPending.length % frameBytes);
      if (usableBytes <= 0) return;
      const usable = this.#pcmPending.subarray(0, usableBytes);
      this.#pcmPending = this.#pcmPending.subarray(usableBytes);
      const samples = new Float32Array(usableBytes / frameBytes);
      for (let index = 0; index < samples.length; index += 1) {
        samples[index] = usable.readFloatLE(index * frameBytes);
      }
      this.#onSamples?.(samples);
    });
    child.stderr?.on("data", () => {});
    child.once("exit", () => { this.#child = null; });
  }

  async feedRtp(packet: Uint8Array): Promise<void> {
    if (!this.#injectSocket) throw new Error("RTP receiver is not started");
    await new Promise<void>((resolve, reject) => {
      this.#injectSocket!.send(packet, this.rtpPort, "127.0.0.1", (error) => {
        if (error) reject(error);
        else resolve();
      });
    });
  }

  async feedRtcp(packet: Uint8Array): Promise<void> {
    if (!this.#injectSocket) throw new Error("RTP receiver is not started");
    await new Promise<void>((resolve, reject) => {
      this.#injectSocket!.send(packet, this.rtcpPort, "127.0.0.1", (error) => {
        if (error) reject(error);
        else resolve();
      });
    });
  }

  stop(): void {
    killChild(this.#child);
    this.#child = null;
    this.#injectSocket?.close();
    this.#injectSocket = null;
    this.#pcmPending = Buffer.alloc(0);
    if (this.#tempDir) {
      fs.rmSync(this.#tempDir, { recursive: true, force: true });
      this.#tempDir = null;
    }
    this.#sdpPath = null;
    this.#started = false;
  }
}
