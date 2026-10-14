/**
 * Engine utilities: JID parsing, relay endpoint decoding, SSRC/stream plan
 * builders, CONNECTION-ID derivation, and env-var helpers. All pure functions
 * with no class state — used by `node.ts` and potentially other relay-layers.
 */

import { createHash } from "node:crypto";

import type { CallInfo } from "../core/types";
import { deriveWasmRelayStreamSsrcs } from "../core/crypto";
import type { RelayInfo, TransportEndpoint, TransportInfo } from "../protocol/xmpp";
import type { RelayStreamSubscriptionEntry } from "../protocol/relay";

export type MutableCallInfo = CallInfo & {
  muted?: boolean;
  videoMuted?: boolean;
};

export const envNumber = (name: string, fallback: number): number => {
  const value = Number(process.env[name]);
  return Number.isFinite(value) && value > 0 ? value : fallback;
};

export const envBool = (name: string, fallback: boolean): boolean => {
  const raw = process.env[name];
  if (raw === undefined || raw === "") {
    return fallback;
  }
  return raw === "1" || raw.toLowerCase() === "true";
};

export const envAudioFilter = (fallback?: string): string | undefined => {
  const raw = process.env.CALL_AUDIO_FILTER;
  if (raw === undefined) {
    return fallback;
  }
  if (raw === "" || raw.toLowerCase() === "none" || raw === "0") {
    return undefined;
  }
  return raw;
};

export const splitJidDevice = (jid: string): { bareJid: string; hasConcreteDevice: boolean } => {
  const atIndex = jid.indexOf("@");
  if (atIndex < 0) {
    return { bareJid: jid, hasConcreteDevice: false };
  }
  const local = jid.slice(0, atIndex);
  const server = jid.slice(atIndex + 1);
  const colonIndex = local.lastIndexOf(":");
  if (colonIndex < 0) {
    return { bareJid: jid, hasConcreteDevice: false };
  }
  const user = local.slice(0, colonIndex);
  const device = local.slice(colonIndex + 1);
  return {
    bareJid: `${user}@${server}`,
    hasConcreteDevice: /^\d+$/.test(device),
  };
};

export const orderOfferDestinations = (jids: readonly string[]): string[] => {
  const seen = new Set<string>();
  const unique = jids
    .map((jid) => String(jid || "").trim())
    .filter((jid) => {
      if (!jid || seen.has(jid)) {
        return false;
      }
      seen.add(jid);
      return true;
    });
  const bare: string[] = [];
  const concrete: string[] = [];
  for (const jid of unique) {
    if (splitJidDevice(jid).hasConcreteDevice) {
      concrete.push(jid);
    } else {
      bare.push(jid);
    }
  }
  return [...bare, ...concrete];
};

export const collectStreamSubscriptionsFromOffer = (
  relay: RelayInfo | undefined,
): RelayStreamSubscriptionEntry[] => {
  if (!relay) {
    return [];
  }
  return [];
};

export const buildDefaultRelayStreamPlan = (
  senderSsrc: number,
  callId?: string,
  selfLidJid?: string,
): RelayStreamSubscriptionEntry[] => {
  if (callId && selfLidJid) {
    const ssrcs = deriveWasmRelayStreamSsrcs(callId, selfLidJid);
    return [
      { participantIndex: 0, streamIndex: 0, ssrc: ssrcs[0]! },
      { participantIndex: 0, streamIndex: 1, ssrc: ssrcs[1]! },
      { participantIndex: 0, streamIndex: 2, ssrc: ssrcs[2]! },
      { participantIndex: 1, streamIndex: 0, ssrc: ssrcs[3]! },
      { participantIndex: 1, streamIndex: 1, ssrc: ssrcs[4]! },
      { participantIndex: 1, streamIndex: 2, ssrc: ssrcs[5]! },
      { participantIndex: 2, streamIndex: 0, ssrc: ssrcs[6]! },
      { participantIndex: 2, streamIndex: 1, ssrc: ssrcs[7]! },
      { participantIndex: 2, streamIndex: 2, ssrc: ssrcs[8]! },
    ];
  }
  const ssrcAt = (offset: number): number => {
    return ((senderSsrc + offset * 0x9e3779b1) >>> 0) || 0xa00b00c0;
  };
  const entries: RelayStreamSubscriptionEntry[] = [];
  for (let stream = 0; stream < 3; stream += 1) {
    for (let index = 0; index < 3; index += 1) {
      entries.push({
        participantIndex: stream,
        streamIndex: index,
        ssrc: ssrcAt(stream * 3 + index),
      });
    }
  }
  return entries;
};

export const decodePrimitiveEndpoint = (
  host: string,
  rawContent: string,
): { ip: string; port: number } | null => {
  const trimmedHost = (host || "").trim();
  const cleaned = (rawContent || "").replace(/[^0-9a-f]/gi, "");
  if (cleaned.length === 12) {
    const bytes = Buffer.from(cleaned, "hex");
    const ip = `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
    const port = bytes.readUInt16BE(4);
    return { ip, port };
  }
  if (cleaned.length === 36) {
    const bytes = Buffer.from(cleaned, "hex");
    const groups: string[] = [];
    for (let index = 0; index < 16; index += 2) {
      groups.push(((bytes[index]! << 8) | bytes[index + 1]!).toString(16));
    }
    const ip = groups.join(":");
    const port = bytes.readUInt16BE(16);
    return { ip, port };
  }
  if (!trimmedHost) {
    return null;
  }
  if (trimmedHost.includes(":") && !trimmedHost.includes("::")) {
    const segments = trimmedHost.split(":");
    const candidatePort = Number.parseInt(segments[segments.length - 1] || "", 10);
    if (Number.isFinite(candidatePort) && segments.length === 2) {
      return { ip: segments[0]!, port: candidatePort };
    }
  }
  return null;
};

export const decodeConnIdHint = (value: string): Uint8Array | undefined => {
  const trimmed = (value || "").trim();
  if (!trimmed) {
    return undefined;
  }
  if (/^[0-9a-f]{16}$/i.test(trimmed)) {
    return Buffer.from(trimmed, "hex");
  }
  return undefined;
};

/** Leading 4 bytes of the relay CONNECTION-ID for IPv4 endpoints. */
const RELAY_CONN_ID_PREFIX = Buffer.from("00012c84", "hex");

/** STUN magic cookie (RFC 5389). */
const STUN_MAGIC_COOKIE = 0x2112a442;

const xorMappedConnId = (ip: string, port: number): Uint8Array | undefined => {
  const octets = ip.split(".");
  if (octets.length !== 4) {
    return undefined;
  }
  const ipBytes = octets.map((o) => Number.parseInt(o, 10));
  if (ipBytes.some((b) => !Number.isInteger(b) || b < 0 || b > 255)) {
    return undefined;
  }
  const out = Buffer.alloc(8);
  out.writeUInt16BE(0x0001, 0);
  out.writeUInt16BE((port ^ (STUN_MAGIC_COOKIE >>> 16)) & 0xffff, 2);
  const ipInt = ((ipBytes[0]! << 24) | (ipBytes[1]! << 16) | (ipBytes[2]! << 8) | ipBytes[3]!) >>> 0;
  out.writeUInt32BE((ipInt ^ STUN_MAGIC_COOKIE) >>> 0, 4);
  return out;
};

/** Derive the relay CONNECTION-ID from an IPv4 endpoint. */
export const deriveRelayConnId = (ip: string, port: number): Uint8Array => {
  const xor = xorMappedConnId(ip, port);
  if (xor) {
    return xor;
  }
  const seed = createHash("sha256").update(`${ip}:${port}`).digest();
  const out = Buffer.alloc(8);
  RELAY_CONN_ID_PREFIX.copy(out, 0);
  seed.copy(out, 4, 0, 4);
  return out;
};
