/**
 * ============================================================================
 * STACK LAYER 2/7 — Relay control <-> signaling glue
 * ============================================================================
 *
 * Converts the `<transport>` XML carried inside call signaling stanzas into the
 * relay-list-update data model the transport and controllers consume
 * (normalising base64/hex tokens, endpoints, conn-ids, keys, warp_mi_tag_len).
 *
 * Why: relay credentials arrive over XMPP (layer 7) but are needed by the relay
 * control layer (layer 2); this is the typed bridge between them. Without this
 * normalization the relay transport can't consume the stanza data.
 */
import { Buffer } from "node:buffer";

import type { TransportEndpoint, TransportInfo } from "../protocol/xmpp";

export interface RelayListAddress {
  protocol: number;
  ipv4?: string;
  ipv6?: string;
  port?: number;
  port_v6?: number;
}

export interface RelayListRelay {
  relay_id: number;
  relay_name: string;
  token_id: number;
  auth_token_id?: number;
  domain_name?: string;
  addresses: RelayListAddress[];
}

export interface RelayListUpdateLike {
  relay_key: string;
  relay_tokens: string[];
  auth_tokens?: string[];
  conn_id?: string;
  enable_edgeray_dtls_active_mode?: boolean;
  relays: RelayListRelay[];
}

const HEX_RE = /^[0-9a-f]+$/i;
const BASE64ISH_RE = /^[A-Za-z0-9+/=]+$/;
const DECIMAL_RE = /^[0-9]+$/;

/**
 * Check if a string looks like hex (even length, only hex chars).
 * Used to decide whether a relay token or conn_id is hex-encoded binary or
 * already base64. The relay server speaks base64 internally, but the XMPP
 * stanzas sometimes carry the raw hex form.
 */
const isHex = (value: string): boolean =>
  value.length > 0 && value.length % 2 === 0 && HEX_RE.test(value);

/** Format 4 raw bytes as an IPv4 dotted-quad string. */
const toIpv4String = (value: Uint8Array): string =>
  `${value[0]}.${value[1]}.${value[2]}.${value[3]}`;

/** Format 16 raw bytes as an IPv6 colon-separated string. */
const toIpv6String = (value: Uint8Array): string => {
  const groups: string[] = [];
  for (let offset = 0; offset < value.length; offset += 2) {
    groups.push(((value[offset]! << 8) | value[offset + 1]!).toString(16));
  }
  return groups.join(":");
};

/** Parse a numeric id from a string attribute, returning -1 on failure. */
const parseNumericId = (value: string): number => {
  const parsed = Number.parseInt(String(value || "").trim(), 10);
  return Number.isFinite(parsed) ? parsed : -1;
};

const normalizeText = (value: string): string => String(value || "").trim();

/** Convert a BigInt to an 8-byte big-endian buffer. */
const bigintToUint64BE = (value: bigint): Uint8Array => {
  const bytes = Buffer.alloc(8);
  let current = value;
  for (let offset = 7; offset >= 0; offset -= 1) {
    bytes[offset] = Number(current & 0xffn);
    current >>= 8n;
  }
  return bytes;
};

/**
 * Normalize a binary token: if it's hex-encoded, decode and re-encode as base64.
 * The relay transport expects all tokens in base64 form.
 */
const normalizeBinaryTokenText = (value: string): string => {
  const normalized = normalizeText(value);
  if (!isHex(normalized)) return normalized;
  return Buffer.from(normalized, "hex").toString("base64");
};

/**
 * Normalize an ASCII-wrapped token: if the text is hex, try decoding it as
 * UTF-8 first (the relay key sometimes comes double-encoded: hex of the
 * base64 string). If that yields base64-looking text, use it. Otherwise
 * keep the raw value.
 */
const normalizeAsciiWrappedText = (value: string): string => {
  const normalized = normalizeText(value);
  if (!isHex(normalized)) return normalized;
  const decoded = Buffer.from(normalized, "hex").toString("utf8").trim();
  if (decoded.length > 0 && BASE64ISH_RE.test(decoded)) return decoded;
  return normalized;
};

export const normalizeRelayTransportValue = (
  value: string,
  mode: "binary" | "ascii-wrapped"
): string =>
  mode === "binary"
    ? normalizeBinaryTokenText(value)
    : normalizeAsciiWrappedText(value);

/**
 * Decode a CONNECTION-ID value from the transport stanza.
 * Supports hex (16-char → 8 bytes), decimal (BigInt → 8 bytes), and base64
 * (8 bytes decoded). Returns null if the value doesn't match any format.
 * Needed because the relay allocate request must carry this 8-byte id to
 * identify which relay endpoint we're allocating.
 */
export const decodeRelayConnId = (value: string): Uint8Array | null => {
  const normalized = normalizeText(value);
  if (!normalized) return null;

  if (isHex(normalized)) {
    const bytes = Buffer.from(normalized, "hex");
    if (bytes.length === 8) return bytes;
  }

  if (DECIMAL_RE.test(normalized)) {
    try {
      const parsed = BigInt(normalized);
      if (parsed >= 0n && parsed <= 0xffffffffffffffffn) return bigintToUint64BE(parsed);
    } catch {}
  }

  if (BASE64ISH_RE.test(normalized) && normalized.length % 4 === 0) {
    try {
      const bytes = Buffer.from(normalized, "base64");
      if (bytes.length === 8) return bytes;
    } catch {}
  }

  return null;
};

/**
 * Decode a hex-encoded relay endpoint blob into an IPv4/IPv6 address + port.
 * The raw hex is 6 bytes for IPv4 (4-byte IP + 2-byte BE port) or 18 bytes
 * for IPv6 (16-byte IP + 2-byte BE port). Returns null for unrecognized
 * lengths.
 */
export const decodeRelayEndpointBytes = (
  rawContent: string
): RelayListAddress | null => {
  const normalized = normalizeText(rawContent);
  if (!isHex(normalized)) return null;

  const bytes = Buffer.from(normalized, "hex");
  if (bytes.length === 6) {
    return { protocol: 0, ipv4: toIpv4String(bytes.subarray(0, 4)), port: bytes.readUInt16BE(4) };
  }
  if (bytes.length === 18) {
    return { protocol: 0, ipv6: toIpv6String(bytes.subarray(0, 16)), port_v6: bytes.readUInt16BE(16) };
  }
  return null;
};

/** Map a protocol string ("udp"/"tcp"/"0"/"1") to a numeric protocol id. */
const resolveEndpointProtocol = (value: string): number => {
  const normalized = normalizeText(value).toLowerCase();
  if (!normalized || normalized === "udp" || normalized === "0") return 0;
  if (normalized === "tcp" || normalized === "1") return 1;
  const parsed = Number.parseInt(normalized, 10);
  return Number.isFinite(parsed) ? parsed : 0;
};

/** Convert a parsed TransportEndpoint to a RelayListAddress. */
const endpointToAddress = (endpoint: TransportEndpoint): RelayListAddress | null => {
  const decoded = decodeRelayEndpointBytes(endpoint.rawContent);
  if (decoded) return { ...decoded, protocol: resolveEndpointProtocol(endpoint.protocol) };

  const host = normalizeText(endpoint.host);
  if (!host) return null;

  const protocol = resolveEndpointProtocol(endpoint.protocol);
  if (host.includes(":")) return { protocol, ipv6: host, port_v6: endpoint.port || undefined };
  return { protocol, ipv4: host, port: endpoint.port || undefined };
};

/** Collect and normalize a credential list (tokens or auth tokens). */
const collectCredentialList = (
  values: Array<{ id: string; value: string }>,
  fallbackValue: string,
  normalizer: (value: string) => string
): string[] => {
  const out: string[] = [];
  for (const value of values) {
    const normalized = normalizer(value.value);
    const id = parseNumericId(value.id);
    if (id >= 0) out[id] = normalized;
    else out.push(normalized);
  }
  if (out.length === 0 && normalizeText(fallbackValue)) out.push(normalizer(fallbackValue));
  return out;
};

/**
 * Convert a TransportInfo (parsed from <transport> inside <relay>) into a
 * RelayListUpdateLike model the transport layer can consume.
 *
 * Why: the XMPP parser produces XML-typed data (tokens as hex strings,
 * endpoints as binary blobs in hex, etc.). The relay transport needs
 * base64 tokens and decoded IP:port addresses. This is the single
 * conversion point.
 */
export const transportToRelayListUpdate = (
  transport: TransportInfo
): RelayListUpdateLike => {
  const relay_tokens = collectCredentialList(
    transport.tokens, transport.token, (value) => normalizeRelayTransportValue(value, "binary")
  );
  const auth_tokens = collectCredentialList(
    transport.authTokens, transport.authToken, (value) => normalizeRelayTransportValue(value, "binary")
  );

  const relay_key = normalizeRelayTransportValue(transport.key, "ascii-wrapped");
  const endpoints = transport.te.length > 0 ? transport.te : transport.te2;
  const relaysById = new Map<number, RelayListRelay>();

  for (const endpoint of endpoints) {
    const relayId = parseNumericId(endpoint.relayId);
    if (relayId < 0) continue;

    const address = endpointToAddress(endpoint);
    if (!address) continue;

    const tokenId = parseNumericId(endpoint.tokenId);
    const authTokenId = parseNumericId(endpoint.authTokenId);
    const existing = relaysById.get(relayId);
    if (existing) {
      existing.addresses.push(address);
      if (!existing.domain_name && endpoint.host && endpoint.host !== address.ipv4 && endpoint.host !== address.ipv6) {
        existing.domain_name = endpoint.host;
      }
      continue;
    }

    relaysById.set(relayId, {
      relay_id: relayId,
      relay_name: normalizeText(endpoint.relayName),
      token_id: tokenId >= 0 ? tokenId : 0,
      auth_token_id: authTokenId >= 0 ? authTokenId : undefined,
      domain_name:
        endpoint.host && endpoint.host !== address.ipv4 && endpoint.host !== address.ipv6
          ? endpoint.host : undefined,
      addresses: [address],
    });
  }

  return {
    conn_id: normalizeText(transport.connId) || undefined,
    relay_key,
    relay_tokens,
    auth_tokens: auth_tokens.length > 0 ? auth_tokens : undefined,
    relays: [...relaysById.values()].sort((left, right) => left.relay_id - right.relay_id),
  };
};
