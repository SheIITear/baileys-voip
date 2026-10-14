/**
 * ============================================================================
 * STACK LAYER 2 — Relay control (per-endpoint state machine)
 * ============================================================================
 *
 * Owns the lifecycle of a single relay endpoint: creating -> allocated -> bound
 * -> ready, with allocate retries, binding-check responses, keepalive and ping
 * timers, and error/failover handling. Emits 'ready' when the relay can carry
 * media so the media pipeline may start.
 *
 * Why: each relay needs independent timing and retry state; the engine runs N of
 * these and converges on the lowest-RTT one. Hands off: drives relay.ts to build
 * messages and the transport (layer 1) to send them; signals readiness upward to
 * WhatsAppVoipNode / mediaPipeline.
 */
/**
 * Pure-Node implementation of the relay control state machine that the
 * WhatsApp WASM stack drives over UDP. One `RelayController` owns a single
 * relay endpoint (an `(ip, port)` pair derived from the offer/accept relay
 * stanza) and walks the lifecycle:
 *
 *   creating  → emit a private allocate request (0x0003)
 *   allocated → relay ack'd the allocate, ready to take binding requests
 *   bound     → relay sent us a binding request, we replied 0x0101
 *   ready     → keepalive loop is active, media path can start
 *
 * The controller doesn't open sockets itself; the caller passes a
 * `send(packet, ip, port)` callback that maps onto whatever transport
 * (`dgram.Socket`, the relay-RTC tunnel, etc.) is appropriate. This keeps
 * the controller hermetic enough to drive from tests with synthetic UDP
 * loops.
 *
 * STUN message types we handle:
 *   - 0x0001 binding request          → respond with 0x0101 binding success
 *   - 0x0101 binding success response → promote to bound
 *   - 0x0103 private allocate response → promote to allocated/bound
 *   - 0x0802 keepalive response       → record keepalive ack
 *   - 0x0805 ping response            → optional, log only
 */
import { randomBytes } from "node:crypto";

import { decodeBase64Bytes } from "../core/bytes";
import {
  buildBindingSuccessResponse,
  buildPrivateAllocateRequest,
  buildPrivateKeepaliveIndication,
  buildRelayPingRequest,
  type RelayStreamSubscriptionEntry,
} from "../protocol/relay";
import { classifyPacket, parseStun, type StunPacket } from "../protocol/protocol";
import { decodeRelayConnId } from "./relayTransport";
import { traceMarker, traceRelayPacket } from "../app/trace";

export type RelayControllerState =
  | "creating"
  | "allocated"
  | "bound"
  | "ready"
  | "closed";

export interface RelayControllerOptions {
  /** Display id used in trace events (e.g. `${ip}:${port}`). */
  id: string;
  /** IP/port the controller will hand to the `send` callback. */
  ip: string;
  port: number;
  /** Relay token (raw bytes); used as the STUN RELAY-TOKEN attribute. */
  relayToken: Uint8Array;
  /** Relay key bytes used for STUN MESSAGE-INTEGRITY HMAC. */
  relayKeyBytes: Uint8Array;
  /** Optional already-decoded transport conn_id. */
  connIdData?: Uint8Array;
  /** Stream subscription plan for the allocate request. */
  streamSubscriptions: readonly RelayStreamSubscriptionEntry[];
  /** Optional logical relay id (e.g. relay descriptor `relay_id`). */
  relayId?: number;
  /** Optional relay name for diagnostic logs. */
  relayName?: string;
  /** Custom keepalive period override (ms). Defaults to env or 1100. */
  keepaliveIntervalMs?: number;
  /** Custom ping period override (ms). Defaults to env or 5000. */
  pingIntervalMs?: number;
  /** Custom retry backoff for un-acked allocate (ms). Defaults to 500. */
  allocateRetryMs?: number;
  /** Optional RNG for transaction ids — useful for deterministic tests. */
  generateTransactionId?: () => Uint8Array;
  /** Optional trace tag. */
  traceTag?: string;
}

type SendFn = (packet: Uint8Array, ip: string, port: number) => unknown;

interface PendingTransaction {
  kind: "allocate" | "binding" | "ping" | "keepalive";
  sentAt: number;
}

const DEFAULT_KEEPALIVE_INTERVAL_MS = Number.parseInt(
  process.env.CALL_RELAY_KEEPALIVE_INTERVAL_MS || "1100",
  10,
) || 1100;
const DEFAULT_PING_INTERVAL_MS = Number.parseInt(
  process.env.CALL_RELAY_PING_INTERVAL_MS || "5000",
  10,
) || 5000;
const DEFAULT_ALLOCATE_RETRY_MS = Number.parseInt(
  process.env.CALL_RELAY_ALLOCATE_RETRY_MS || "500",
  10,
) || 500;

const STUN_BINDING_REQUEST = 0x0001;
const STUN_BINDING_SUCCESS = 0x0101;
const STUN_PRIVATE_ALLOCATE_REQUEST = 0x0003;
const STUN_PRIVATE_ALLOCATE_RESPONSE = 0x0103;
// Allocate ERROR response: same method (0x003) with the STUN error class
// bits set (0x0113). The relay sends this to REJECT an allocate, e.g.
// ERROR-CODE 452 "Xor Relayed Address Mismatch" when the CONNECTION-ID we
// present resolves to a different relay address than the one we sent the
// datagram to. We MUST treat the relay as unusable so media never targets it.
const STUN_PRIVATE_ALLOCATE_ERROR = 0x0113;
const STUN_PRIVATE_KEEPALIVE_RESPONSE = 0x0802;
const STUN_PRIVATE_PING_RESPONSE = 0x0805;

const decodeStunConnId = (stun: StunPacket): Uint8Array | undefined => {
  for (const attribute of stun.attributes) {
    if (attribute.attrType === 0x0016 && attribute.value.length === 8) {
      return attribute.value;
    }
  }
  return undefined;
};

/** Decode the STUN ERROR-CODE (attr 0x0009) into a numeric code + reason. */
const decodeStunError = (
  stun: StunPacket,
): { code: number; reason: string } | undefined => {
  for (const attribute of stun.attributes) {
    if (attribute.attrType === 0x0009 && attribute.value.length >= 4) {
      const v = attribute.value;
      const cls = (v[2] as number) & 0x07;
      const num = v[3] as number;
      const reason = Buffer.from(v.subarray(4)).toString("utf8");
      return { code: cls * 100 + num, reason };
    }
  }
  return undefined;
};

const ensureBuffer = (value: Uint8Array): Buffer =>
  value instanceof Buffer
    ? value
    : Buffer.from(value.buffer, value.byteOffset, value.byteLength);

const transactionKey = (transactionId: Uint8Array): string =>
  ensureBuffer(transactionId).toString("hex");

/**
 * Lightweight typed event-emitter that doesn't require pulling in
 * `node:events` (and matches the project's "no globals" convention).
 */
class TinyEmitter<TEvents extends Record<string, unknown>> {
  #listeners: { [K in keyof TEvents]?: Array<(event: TEvents[K]) => void> } = {};

  on<K extends keyof TEvents>(event: K, listener: (event: TEvents[K]) => void): this {
    (this.#listeners[event] ??= []).push(listener);
    return this;
  }

  off<K extends keyof TEvents>(event: K, listener: (event: TEvents[K]) => void): this {
    const list = this.#listeners[event];
    if (!list) return this;
    const index = list.indexOf(listener);
    if (index >= 0) list.splice(index, 1);
    return this;
  }

  emit<K extends keyof TEvents>(event: K, payload: TEvents[K]): void {
    const list = this.#listeners[event];
    if (!list) return;
    for (const listener of [...list]) {
      try { listener(payload); } catch {}
    }
  }
}

export interface RelayControllerEvents extends Record<string, unknown> {
  state: { previous: RelayControllerState; current: RelayControllerState };
  ready: { id: string };
  closed: { id: string; reason: string };
  /** Relay rejected our allocate (0x0113). The relay is unusable. */
  allocate_error: { id: string; code: number; reason: string };
  log: { level: "log" | "warn" | "error"; message: string; details?: Record<string, unknown> };
}

/**
 * Drives the STUN-allocate / STUN-bind / keepalive / ping lifecycle for a
 * single relay endpoint. The controller is purely event-driven: callers
 * feed it incoming STUN datagrams via `handleIncomingStun(packet)` and
 * the controller emits `state` / `ready` / `closed` events as it moves
 * through the lifecycle.
 */
export class RelayController extends TinyEmitter<RelayControllerEvents> {
  readonly id: string;
  readonly ip: string;
  readonly port: number;
  readonly relayId?: number;
  readonly relayName?: string;
  readonly keepaliveIntervalMs: number;
  readonly pingIntervalMs: number;
  readonly allocateRetryMs: number;

  #relayToken: Uint8Array;
  #relayKeyBytes: Uint8Array;
  #streamSubscriptions: RelayStreamSubscriptionEntry[];
  #generateTransactionId: () => Uint8Array;
  #traceTag?: string;
  #connIdData: Uint8Array;
  #state: RelayControllerState = "creating";
  #send: SendFn | null = null;
  #allocateTimer: NodeJS.Timeout | null = null;
  #keepaliveTimer: NodeJS.Timeout | null = null;
  #pingTimer: NodeJS.Timeout | null = null;
  #pending = new Map<string, PendingTransaction>();
  #allocateAttempts = 0;
  #bindAttempts = 0;
  #pingAttempts = 0;
  #keepaliveAttempts = 0;
  #lastAllocateAt = 0;
  #lastKeepaliveAt = 0;
  #lastPingAt = 0;
  #readyEmitted = false;

  constructor(options: RelayControllerOptions) {
    super();
    this.id = options.id;
    this.ip = options.ip;
    this.port = options.port;
    this.relayId = options.relayId;
    this.relayName = options.relayName;
    this.keepaliveIntervalMs = Math.max(250, options.keepaliveIntervalMs ?? DEFAULT_KEEPALIVE_INTERVAL_MS);
    this.pingIntervalMs = Math.max(500, options.pingIntervalMs ?? DEFAULT_PING_INTERVAL_MS);
    this.allocateRetryMs = Math.max(250, options.allocateRetryMs ?? DEFAULT_ALLOCATE_RETRY_MS);
    this.#relayToken = options.relayToken;
    this.#relayKeyBytes = options.relayKeyBytes;
    this.#streamSubscriptions = [...options.streamSubscriptions];
    this.#generateTransactionId = options.generateTransactionId ?? (() => new Uint8Array(randomBytes(12)));
    this.#traceTag = options.traceTag;
    this.#connIdData = options.connIdData ?? new Uint8Array(8);
  }

  getState(): RelayControllerState {
    return this.#state;
  }

  getStats(): {
    state: RelayControllerState;
    allocateAttempts: number;
    bindAttempts: number;
    pingAttempts: number;
    keepaliveAttempts: number;
    pendingTransactions: number;
    connIdHex: string;
  } {
    return {
      state: this.#state,
      allocateAttempts: this.#allocateAttempts,
      bindAttempts: this.#bindAttempts,
      pingAttempts: this.#pingAttempts,
      keepaliveAttempts: this.#keepaliveAttempts,
      pendingTransactions: this.#pending.size,
      connIdHex: ensureBuffer(this.#connIdData).toString("hex"),
    };
  }

  start(send: SendFn): void {
    if (this.#state === "closed") {
      throw new Error(`RelayController ${this.id} already closed`);
    }
    this.#send = send;
    this.#transition("creating");
    this.#sendAllocate();
    this.#allocateTimer = setInterval(() => {
      if (this.#state === "creating") {
        this.#sendAllocate();
      } else if (this.#allocateTimer) {
        clearInterval(this.#allocateTimer);
        this.#allocateTimer = null;
      }
    }, this.allocateRetryMs);
    if (this.#allocateTimer.unref) {
      this.#allocateTimer.unref();
    }
  }

  close(reason = "manual"): void {
    if (this.#state === "closed") {
      return;
    }
    this.#clearTimers();
    this.#send = null;
    this.#transition("closed");
    this.emit("closed", { id: this.id, reason });
  }

  handleIncomingStun(packet: Uint8Array): boolean {
    if (classifyPacket(packet) !== "stun") {
      return false;
    }
    let stun: StunPacket;
    try {
      stun = parseStun(packet);
    } catch (error) {
      this.emit("log", {
        level: "warn",
        message: "invalid STUN packet",
        details: { id: this.id, error: String(error) },
      });
      return false;
    }
    traceRelayPacket("recv", packet, "stun", {
      stunType: stun.msgType,
      ip: this.ip,
      port: this.port,
      relayName: this.relayName,
    });

    switch (stun.msgType) {
      case STUN_BINDING_REQUEST:
        this.#respondBindingRequest(stun);
        return true;
      case STUN_BINDING_SUCCESS: {
        const tk = transactionKey(stun.transactionId);
        const pending = this.#pending.get(tk);
        if (pending) {
          this.#pending.delete(tk);
        }
        this.#promoteToBound("binding-success");
        return true;
      }
      case STUN_PRIVATE_ALLOCATE_ERROR: {
        const err = decodeStunError(stun);
        const code = err?.code ?? 0;
        const reason = err?.reason ?? "";
        const tk = transactionKey(stun.transactionId);
        this.#pending.delete(tk);
        this.emit("log", {
          level: "warn",
          message: "relay rejected allocate",
          details: { id: this.id, code, reason },
        });
        this.emit("allocate_error", { id: this.id, code, reason });
        this.close(`allocate-error-${code}`);
        return true;
      }
      case STUN_PRIVATE_ALLOCATE_RESPONSE: {
        const tk = transactionKey(stun.transactionId);
        if (!this.#pending.has(tk)) {
          // Not a transaction we initiated; still treat it as authoritative
        } else {
          this.#pending.delete(tk);
        }
        const conn = decodeStunConnId(stun);
        if (conn) {
          this.#connIdData = conn;
        }
        if (this.#state === "creating") {
          this.#transition("allocated");
        }
        this.#promoteToBound("allocate-success");
        return true;
      }
      case STUN_PRIVATE_KEEPALIVE_RESPONSE: {
        const tk = transactionKey(stun.transactionId);
        this.#pending.delete(tk);
        return true;
      }
      case STUN_PRIVATE_PING_RESPONSE: {
        const tk = transactionKey(stun.transactionId);
        this.#pending.delete(tk);
        return true;
      }
      default:
        this.emit("log", {
          level: "log",
          message: "unhandled STUN message type",
          details: { id: this.id, msgType: stun.msgType },
        });
        return false;
    }
  }

  adoptConnId(value: Uint8Array | string | undefined): void {
    if (!value) return;
    if (typeof value === "string") {
      const decoded = decodeRelayConnId(value);
      if (decoded) this.#connIdData = decoded;
      return;
    }
    if (value.byteLength === 8) this.#connIdData = value;
  }

  #transition(next: RelayControllerState): void {
    if (this.#state === next) return;
    const previous = this.#state;
    this.#state = next;
    this.emit("state", { previous, current: next });
    traceMarker("relay_controller_state", {
      id: this.id, previous, current: next, tag: this.#traceTag,
    });
  }

  #promoteToBound(reason: string): void {
    if (this.#state !== "bound" && this.#state !== "ready") {
      this.#transition("bound");
    }
    if (!this.#keepaliveTimer) {
      this.#sendKeepalive();
      this.#keepaliveTimer = setInterval(() => this.#sendKeepalive(), this.keepaliveIntervalMs);
      if (this.#keepaliveTimer.unref) this.#keepaliveTimer.unref();
    }
    if (this.#allocateTimer) {
      clearInterval(this.#allocateTimer);
      this.#allocateTimer = null;
    }
    if (this.#state !== "ready") {
      this.#transition("ready");
    }
    if (!this.#readyEmitted) {
      this.#readyEmitted = true;
      this.emit("ready", { id: this.id });
    }
    void reason;
  }

  #respondBindingRequest(stun: StunPacket): void {
    const response = buildBindingSuccessResponse({
      transactionId: stun.transactionId,
      messageIntegrityKey: this.#relayKeyBytes,
    });
    this.#dispatch(response);
    traceRelayPacket("send", response, "stun", {
      stunType: STUN_BINDING_SUCCESS,
      ip: this.ip, port: this.port, relayName: this.relayName,
      classification: "binding-success-response",
    });
    if (this.#state === "creating" || this.#state === "allocated") {
      this.#promoteToBound("binding-request");
    }
  }

  #sendAllocate(): void {
    const transactionId = this.#generateTransactionId();
    const packet = buildPrivateAllocateRequest({
      transactionId,
      relayToken: this.#relayToken,
      streamSubscriptions: this.#streamSubscriptions,
      connIdData: this.#connIdData,
      messageIntegrityKey: this.#relayKeyBytes,
    });
    this.#allocateAttempts += 1;
    this.#lastAllocateAt = Date.now();
    this.#pending.set(transactionKey(transactionId), {
      kind: "allocate", sentAt: this.#lastAllocateAt,
    });
    this.#dispatch(packet);
    traceRelayPacket("send", packet, "stun", {
      stunType: STUN_PRIVATE_ALLOCATE_REQUEST,
      ip: this.ip, port: this.port, relayName: this.relayName,
      classification: "private-allocate-request",
    });
  }

  #sendKeepalive(): void {
    const transactionId = this.#generateTransactionId();
    const packet = buildPrivateKeepaliveIndication(transactionId);
    this.#keepaliveAttempts += 1;
    this.#lastKeepaliveAt = Date.now();
    this.#pending.set(transactionKey(transactionId), {
      kind: "keepalive", sentAt: this.#lastKeepaliveAt,
    });
    this.#dispatch(packet);
    traceRelayPacket("send", packet, "stun", {
      ip: this.ip, port: this.port, relayName: this.relayName,
      classification: "private-keepalive-indication",
    });
  }

  #sendPing(): void {
    const transactionId = this.#generateTransactionId();
    const packet = buildRelayPingRequest({
      transactionId,
      connIdData: this.#connIdData,
      messageIntegrityKey: this.#relayKeyBytes,
    });
    this.#pingAttempts += 1;
    this.#lastPingAt = Date.now();
    this.#pending.set(transactionKey(transactionId), {
      kind: "ping", sentAt: this.#lastPingAt,
    });
    this.#dispatch(packet);
    traceRelayPacket("send", packet, "stun", {
      ip: this.ip, port: this.port, relayName: this.relayName,
      classification: "private-ping-request",
    });
  }

  #dispatch(packet: Uint8Array): void {
    if (!this.#send) return;
    try {
      this.#send(packet, this.ip, this.port);
    } catch (error) {
      this.emit("log", {
        level: "warn", message: "send failed",
        details: { id: this.id, error: String(error) },
      });
    }
  }

  #clearTimers(): void {
    if (this.#allocateTimer) { clearInterval(this.#allocateTimer); this.#allocateTimer = null; }
    if (this.#keepaliveTimer) { clearInterval(this.#keepaliveTimer); this.#keepaliveTimer = null; }
    if (this.#pingTimer) { clearInterval(this.#pingTimer); this.#pingTimer = null; }
    this.#pending.clear();
  }
}

export const decodeRelayKeyBytes = (value: string): Uint8Array =>
  decodeBase64Bytes(value);
