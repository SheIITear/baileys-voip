/**
 * ============================================================================
 * CROSS-CUTTING — Observability (JSONL tracer)
 * ============================================================================
 *
 * Structured JSONL tracer with parity to the WASM caller's tracer: markers,
 * stanzas, relay packets and PCM blobs, for offline diffing against the official
 * client.
 *
 * Why: byte-level parity debugging against WhatsApp Web.
 */
/**
 * WASM-grade tracer for the pure Node.js stack. This module mirrors the
 * format and helpers exported by `baileys-caller-main/src/wasm-trace.mts`
 * so a single side-by-side diff of the two JSONL streams can prove parity
 * between the WASM-backed engine and the pure-Node replacement.
 *
 * Output:
 *   - `<cwd>/logs/node-load-trace-<ts>.jsonl` — one JSON event per line
 *   - `<cwd>/logs/node-load-trace-blobs-<ts>/` — overflow buckets for
 *     payloads larger than `CALL_TRACE_HEX_INLINE_LIMIT`
 *
 * Environment knobs (parity with the WASM tracer):
 *   - `CALL_DUMP_NODE_TRACE=0`        disable the tracer entirely
 *   - `CALL_DUMP_NODE_TRACE_PATH=...` override the output file path
 *   - `CALL_TRACE_HEX_INLINE_LIMIT`   max inline bytes before spilling to a
 *                                     side blob (default 4096)
 *   - `CALL_TRACE_PCM_SAMPLE`         sample rate for audio_pcm events
 *   - `CALL_TRACE_MEDIA_BYTES=0`      disable clear-media byte traces
 *
 * The envelope is `{ts, ts_ns, seq, thread, op, data}` exactly as the WASM
 * tracer emits, with the same `op` enum so logs can be merged or compared
 * line-by-line.
 *
 * @author ShellTear
 */
import {
  appendFileSync,
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { resolve as resolvePath } from "node:path";
import { performance } from "node:perf_hooks";

const TRACE_ENABLED = process.env.CALL_DUMP_NODE_TRACE !== "0";
const TRACE_PATH_OVERRIDE = process.env.CALL_DUMP_NODE_TRACE_PATH ?? "";
const HEX_INLINE_LIMIT = Number(process.env.CALL_TRACE_HEX_INLINE_LIMIT) || 4096;

let resolvedPath: string | null = null;
let blobsDir: string | null = null;
let fd: number | null = null;
let blobCounter = 0;
let lineCounter = 0;
const startWallMs = Date.now();
const startPerfMs = performance.now();

export type TraceOp =
  | "marker"
  | "stanza"
  | "relay_packet"
  | "ab_prop"
  | "voip_setting"
  | "call_event"
  | "call_info_snapshot"
  | "audio_pcm"
  | "media_packet"
  | "log_line"
  | "wasm_call"
  | "wasm_call_return"
  | "wasm_callback"
  | "wasm_callback_return";

export interface TraceEvent {
  /** UTC ISO-8601 with millisecond resolution. */
  ts: string;
  /** Monotonic high-resolution timestamp in nanoseconds since process start. */
  ts_ns: number;
  /** Sequence number — unique per writer, monotone. */
  seq: number;
  /** Thread / worker identity. "main" or `worker:<id>`. */
  thread: string;
  /** High-level event family. */
  op: TraceOp;
  /** Free-form payload. */
  data: Record<string, unknown>;
}

const resolvePaths = (): { trace: string | null; blobs: string | null } => {
  if (!TRACE_ENABLED) {
    return { trace: null, blobs: null };
  }
  if (resolvedPath) {
    return { trace: resolvedPath, blobs: blobsDir };
  }
  if (TRACE_PATH_OVERRIDE) {
    resolvedPath = TRACE_PATH_OVERRIDE;
  } else {
    const logDir = resolvePath(process.cwd(), "logs");
    try {
      if (!existsSync(logDir)) {
        mkdirSync(logDir, { recursive: true });
      }
    } catch {}
    const ts = new Date().toISOString().replace(/[:.]/g, "-");
    resolvedPath = resolvePath(logDir, `node-load-trace-${ts}.jsonl`);
    blobsDir = resolvePath(logDir, `node-load-trace-blobs-${ts}`);
    try {
      if (!existsSync(blobsDir)) {
        mkdirSync(blobsDir, { recursive: true });
      }
    } catch {}
  }
  // eslint-disable-next-line no-console
  console.log(`[node-trace] dumping to ${resolvedPath} (blobs in ${blobsDir})`);
  return { trace: resolvedPath, blobs: blobsDir };
};

const openIfNeeded = (): number | null => {
  if (!TRACE_ENABLED) {
    return null;
  }
  if (fd !== null) {
    return fd;
  }
  const { trace } = resolvePaths();
  if (!trace) {
    return null;
  }
  try {
    fd = openSync(trace, "a");
  } catch {
    fd = null;
  }
  return fd;
};

const isPrimitive = (value: unknown): boolean =>
  value === null ||
  value === undefined ||
  typeof value === "string" ||
  typeof value === "number" ||
  typeof value === "boolean" ||
  typeof value === "bigint";

const isTypedArray = (value: any): value is Uint8Array =>
  value &&
  typeof value === "object" &&
  typeof value.byteLength === "number" &&
  typeof value.BYTES_PER_ELEMENT === "number";

/**
 * Best-effort serialization of an arbitrary JS value:
 *  - primitives: as-is (bigints become strings)
 *  - typed arrays / Buffer / ArrayBuffer: { kind: "TypedArray", ctor, length, hex_prefix, hex_full?, blob_id?, byteLength }
 *    `hex_full` is inlined when within HEX_INLINE_LIMIT; larger payloads
 *    are spilled to a side file under the blobs directory.
 *  - Functions: { kind: "Function", name }
 *  - Plain objects: shallow-cloned via JSON dance with a circular guard.
 */
export const serializeValue = (value: unknown): unknown => {
  if (isPrimitive(value)) {
    if (typeof value === "bigint") {
      return value.toString();
    }
    return value;
  }
  if (typeof value === "function") {
    return { kind: "Function", name: (value as Function).name || "anonymous" };
  }
  if (typeof value !== "object" || value === null) {
    return null;
  }
  if (
    isTypedArray(value) ||
    value instanceof ArrayBuffer ||
    (typeof Buffer !== "undefined" && Buffer.isBuffer(value))
  ) {
    const u8 =
      value instanceof ArrayBuffer
        ? new Uint8Array(value)
        : (value as any).BYTES_PER_ELEMENT === 1
          ? (value as Uint8Array)
          : new Uint8Array(
              (value as any).buffer,
              (value as any).byteOffset,
              (value as any).byteLength,
            );
    const ctor = (value as any).constructor?.name ?? "Uint8Array";
    const inline = u8.byteLength <= HEX_INLINE_LIMIT;
    let hexFull: string | undefined;
    let blobId: string | undefined;
    if (inline) {
      hexFull = Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength).toString(
        "hex",
      );
    } else {
      const id = `blob-${(blobCounter += 1).toString(36)}`;
      const { blobs } = resolvePaths();
      if (blobs) {
        try {
          writeFileSync(
            resolvePath(blobs, `${id}.bin`),
            Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength),
          );
          blobId = id;
        } catch {}
      }
    }
    return {
      kind: "TypedArray",
      ctor,
      byteLength: u8.byteLength,
      hex_prefix: Buffer.from(
        u8.buffer,
        u8.byteOffset,
        Math.min(u8.byteLength, 64),
      ).toString("hex"),
      hex_full: hexFull,
      blob_id: blobId,
    };
  }
  try {
    const seen = new WeakSet<object>();
    return JSON.parse(
      JSON.stringify(value, (_k, raw) => {
        if (typeof raw === "object" && raw !== null) {
          if (seen.has(raw)) {
            return "<cycle>";
          }
          seen.add(raw);
        }
        if (typeof raw === "bigint") {
          return raw.toString();
        }
        return raw;
      }),
    );
  } catch {
    return { kind: "Unserializable", className: (value as any).constructor?.name };
  }
};

const serializeArgs = (args: ArrayLike<unknown>): unknown[] => {
  const out: unknown[] = [];
  for (let index = 0; index < args.length; index += 1) {
    out.push(serializeValue(args[index]));
  }
  return out;
};

export const trace = (
  op: TraceOp,
  data: Record<string, unknown>,
  thread = "main",
): void => {
  const file = openIfNeeded();
  if (file === null) {
    return;
  }
  const tsNs = Math.round((performance.now() - startPerfMs) * 1_000_000);
  const ts = new Date(
    startWallMs + (performance.now() - startPerfMs),
  ).toISOString();
  const seq = (lineCounter += 1);
  const event: TraceEvent = { ts, ts_ns: tsNs, seq, thread, op, data };
  try {
    writeSync(file, JSON.stringify(event) + "\n");
  } catch {
    try {
      appendFileSync(resolvedPath ?? "", JSON.stringify(event) + "\n");
    } catch {}
  }
};

export const traceMarker = (
  label: string,
  extra: Record<string, unknown> = {},
): void => trace("marker", { label, ...extra });

export const traceFlush = (): void => {
  if (fd !== null) {
    try {
      closeSync(fd);
    } catch {}
    fd = null;
  }
};

export const traceStanza = (
  direction: "in" | "out",
  node: unknown,
  extra: Record<string, unknown> = {},
): void => trace("stanza", { direction, node: serializeValue(node), ...extra });

export const traceCallEvent = (
  eventType: number,
  eventData: unknown,
  extra: Record<string, unknown> = {},
): void =>
  trace("call_event", {
    eventType,
    eventData: serializeValue(eventData),
    ...extra,
  });

export const traceCallInfoSnapshot = (snapshot: unknown): void =>
  trace("call_info_snapshot", { snapshot: serializeValue(snapshot) });

export const traceAbProp = (
  name: string,
  value: unknown,
  accepted: boolean,
  error?: string,
): void => trace("ab_prop", { name, value, accepted, error });

export const traceVoipSetting = (settings: unknown): void =>
  trace("voip_setting", { settings: serializeValue(settings) });

export const traceLogLine = (
  level: string,
  message: string,
  source = "node",
): void => trace("log_line", { level, source, message });

const PCM_COUNTERS: Record<string, number> = {};

export const traceAudioPcm = (
  direction: "tx" | "rx",
  pcm: Float32Array,
  meta: {
    sampleRate?: number;
    channels?: number;
    framesPerChunk?: number;
    ptr?: number;
  } = {},
): void => {
  const counter = (PCM_COUNTERS[direction] =
    (PCM_COUNTERS[direction] || 0) + 1);
  const sampleEvery = Number(process.env.CALL_TRACE_PCM_SAMPLE) || 25;
  if (counter > 5 && counter % sampleEvery !== 0) {
    return;
  }
  const u8 = new Uint8Array(pcm.buffer, pcm.byteOffset, pcm.byteLength);
  let rmsAcc = 0;
  let peak = 0;
  for (let index = 0; index < pcm.length; index += 1) {
    const sample = pcm[index]!;
    rmsAcc += sample * sample;
    const abs = Math.abs(sample);
    if (abs > peak) {
      peak = abs;
    }
  }
  const summary = {
    direction,
    chunkIndex: counter,
    samples: pcm.length,
    rms: Math.sqrt(rmsAcc / Math.max(1, pcm.length)),
    peak,
    hex_prefix: Buffer.from(
      u8.buffer,
      u8.byteOffset,
      Math.min(u8.byteLength, 128),
    ).toString("hex"),
    sampleRate: meta.sampleRate,
    channels: meta.channels,
    framesPerChunk: meta.framesPerChunk,
    ptr: meta.ptr,
  };
  trace("audio_pcm", summary);
};

export type MediaPacketStage =
  | "ffmpeg_rtp"
  | "opus_payload"
  | "srtp_self_decrypt"
  | "recv_cleartext"
  | "pacer_tick";

const MEDIA_BYTES_ENABLED = process.env.CALL_TRACE_MEDIA_BYTES !== "0";

export const traceMediaPacket = (
  stage: MediaPacketStage,
  packet: Uint8Array,
  meta: Record<string, unknown> = {},
): void => {
  if (!MEDIA_BYTES_ENABLED) {
    return;
  }
  const u8 =
    packet instanceof Uint8Array
      ? packet
      : new Uint8Array(
          (packet as any).buffer,
          (packet as any).byteOffset,
          (packet as any).byteLength,
        );
  trace("media_packet", {
    stage,
    byteLength: u8.byteLength,
    bytes: serializeValue(u8),
    ...meta,
  });
};

export type RelayPacketDirection = "send" | "recv";
export type RelayPacketKind = "rtp" | "rtcp" | "stun" | "dtls" | "unknown";

export interface RelayPacketTraceMeta {
  ip?: string;
  port?: number;
  callId?: string;
  relayName?: string;
  ssrc?: number;
  sequenceNumber?: number;
  payloadType?: number;
  stunType?: number;
  decryptOk?: boolean;
  decryptError?: string;
  selfDecryptOk?: boolean;
  selfDecryptError?: string;
  classification?: string;
  rocAfter?: number;
  rtcpIndex?: number;
}

export const traceRelayPacket = (
  direction: RelayPacketDirection,
  packet: Uint8Array,
  kind: RelayPacketKind,
  meta: RelayPacketTraceMeta = {},
): void => {
  const u8 =
    packet instanceof Uint8Array
      ? packet
      : new Uint8Array(
          (packet as any).buffer,
          (packet as any).byteOffset,
          (packet as any).byteLength,
        );
  const inline = u8.byteLength <= HEX_INLINE_LIMIT;
  let hexFull: string | undefined;
  let blobId: string | undefined;
  if (inline) {
    hexFull = Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength).toString(
      "hex",
    );
  } else {
    const id = `blob-${(blobCounter += 1).toString(36)}`;
    const { blobs } = resolvePaths();
    if (blobs) {
      try {
        writeFileSync(
          resolvePath(blobs, `${id}.bin`),
          Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength),
        );
        blobId = id;
      } catch {}
    }
  }
  trace("relay_packet", {
    direction,
    kind,
    byteLength: u8.byteLength,
    hex_prefix: Buffer.from(
      u8.buffer,
      u8.byteOffset,
      Math.min(u8.byteLength, 64),
    ).toString("hex"),
    hex_full: hexFull,
    blob_id: blobId,
    ...meta,
  });
};

/**
 * Wrap an arbitrary callbacks bag so each fired callback emits a
 * `wasm_callback` / `wasm_callback_return` event pair. The wrappers
 * preserve return values and re-throw errors after logging them.
 */
export const wrapCallbacks = <T extends Record<string, any>>(callbacks: T): T => {
  if (!TRACE_ENABLED || !callbacks) {
    return callbacks;
  }
  const out: Record<string, any> = {};
  for (const [name, fn] of Object.entries(callbacks)) {
    if (typeof fn !== "function") {
      out[name] = fn;
      continue;
    }
    out[name] = function (this: any, ...args: any[]) {
      const t0 = performance.now();
      const callId = (lineCounter + 1).toString(36);
      trace("wasm_callback", { callId, name, args: serializeArgs(args) });
      try {
        const result = fn.apply(this, args);
        if (result && typeof result.then === "function") {
          result.then(
            (value: unknown) =>
              trace("wasm_callback_return", {
                callId,
                name,
                return: serializeValue(value),
                duration_ns: Math.round(
                  (performance.now() - t0) * 1_000_000,
                ),
                async: true,
              }),
            (error: unknown) =>
              trace("wasm_callback_return", {
                callId,
                name,
                error: String(error),
                duration_ns: Math.round(
                  (performance.now() - t0) * 1_000_000,
                ),
                async: true,
              }),
          );
          return result;
        }
        trace("wasm_callback_return", {
          callId,
          name,
          return: serializeValue(result),
          duration_ns: Math.round((performance.now() - t0) * 1_000_000),
        });
        return result;
      } catch (error) {
        trace("wasm_callback_return", {
          callId,
          name,
          error: String(error),
          duration_ns: Math.round((performance.now() - t0) * 1_000_000),
        });
        throw error;
      }
    };
  }
  return out as T;
};
