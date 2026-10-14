/**
 * ============================================================================
 * STACK LAYER 0 — Packet classification / demux
 * ============================================================================
 *
 * Entry point for every datagram arriving from the relay transport. Sniffs the
 * first bytes to classify a packet as STUN (relay control), DTLS, RTP, or RTCP,
 * then parses headers and builds the structured `DatagramInfo` the upper layers
 * consume. Also holds the shared byte-level builders/parsers (RTP/RTCP headers,
 * STUN attributes, XOR-MAPPED-ADDRESS) reused by the relay and media layers.
 *
 * Why: the relay multiplexes control and media on one channel, so a single,
 * correct demuxer must run before anything else can route a packet. Hands off:
 * STUN -> relay/relayController; RTP/RTCP -> srtp/rtpEngine via mediaPipeline.
 */
/**
 * Network-layer protocol classification and parsing for WhatsApp VoIP traffic.
 *
 * Identifies UDP datagrams by content: STUN (binding/allocate), DTLS (relay
 * handshake), RTP (media packets), and RTCP (control packets). Provides full
 * packet parsers (parseStun, parseRtp, parseRtcp, parseDtls) and packet
 * builders (buildRtpPacket, buildRtcpSenderReport, buildRtcpSourceDescription)
 * plus WhatsApp-proprietary WARP control packet builders (transport-feedback
 * PT208, stream-hello PT209, application-feedback PT206) and STUN XOR-address
 * encoding/decoding for relay endpoint resolution.
 */

import {
  readUint16BE,
  readUint32BE,
  uint32ToBytes,
  writeUint16BE,
  writeUint32BE,
} from "../core/bytes";

export type PacketKind =
  | "unknown"
  | "stun"
  | "dtls"
  | "rtp"
  | "rtcp"
  | "sctp-or-unknown-l4";

export interface StunAttribute {
  attrType: number;
  value: Uint8Array;
}

export interface StunPacket {
  msgType: number;
  length: number;
  magicCookie: number;
  transactionId: Uint8Array;
  attributes: StunAttribute[];
}

export interface DtlsRecord {
  contentType: number;
  versionMajor: number;
  versionMinor: number;
  epoch: number;
  sequenceNumber: bigint;
  length: number;
}

export interface RtpPacket {
  payloadType: number;
  marker: boolean;
  sequenceNumber: number;
  timestamp: number;
  ssrc: number;
  csrcs: number[];
  hasExtension: boolean;
  extensionProfile: number | null;
  extensionData: Uint8Array | null;
  headerLength: number;
  payload: Uint8Array;
}

export interface RtcpPacket {
  packetType: number;
  count: number;
  lengthWords: number;
  body: Uint8Array;
}

export interface DatagramInfo {
  kind: PacketKind;
  raw: Uint8Array;
  sourceHost: string;
  sourcePort: number;
  dtls?: DtlsRecord;
  stun?: StunPacket;
  rtp?: RtpPacket;
  rtcp?: RtcpPacket;
}

export const StunMagicCookie = 0x2112a442;

/** Check if a datagram is a STUN packet (magic cookie at offset 4, top 2 bits of byte 0 are 0). */
const isStun = (data: Uint8Array): boolean =>
  data.length >= 20 &&
  (data[0]! & 0xc0) === 0 &&
  readUint32BE(data, 4) === StunMagicCookie;

/** Check if a datagram is a DTLS record (first byte in 20-25 range, 0xfe 0xfd/0xff following). */
const isDtls = (data: Uint8Array): boolean =>
  data.length >= 13 &&
  data[0]! >= 20 &&
  data[0]! <= 25 &&
  data[1] === 0xfe &&
  (data[2] === 0xfd || data[2] === 0xff);

const isRtpVersion2 = (data: Uint8Array): boolean =>
  data.length >= 12 && (data[0]! >>> 6) === 2;

/** Check if a datagram is RTCP (RTP version 2 with payload type in 192-223 range). */
const isRtcp = (data: Uint8Array): boolean => {
  if (!isRtpVersion2(data) || data.length < 8) return false;
  const payloadType = data[1]!;
  return payloadType >= 192 && payloadType <= 223;
};

/** Check if a datagram is RTP (version 2, payload type is non-RTCP range). */
const isRtp = (data: Uint8Array): boolean => {
  if (!isRtpVersion2(data) || data.length < 12) return false;
  const payloadType = data[1]! & 0x7f;
  return payloadType < 64 || payloadType >= 96;
};

/**
 * Classify a UDP datagram by sniffing the first bytes.
 * The relay multiplexes STUN (relay control), DTLS (data channel), RTP (media),
 * and RTCP (control) on the same UDP flow, so this is the single demux point.
 */
export const classifyPacket = (data: Uint8Array): PacketKind => {
  if (isStun(data)) {
    return "stun";
  }
  if (isDtls(data)) {
    return "dtls";
  }
  if (isRtcp(data)) {
    return "rtcp";
  }
  if (isRtp(data)) {
    return "rtp";
  }
  if (data.length >= 12) {
    return "sctp-or-unknown-l4";
  }
  return "unknown";
};

/**
 * Parse a STUN packet: message type, magic cookie, transaction id, and attributes.
 * Used by the relay control layer to process binding/allocate responses.
 */
export const parseStun = (data: Uint8Array): StunPacket => {
  if (data.length < 20) {
    throw new Error("STUN packet too short");
  }
  const packet: StunPacket = {
    msgType: readUint16BE(data, 0),
    length: readUint16BE(data, 2),
    magicCookie: readUint32BE(data, 4),
    transactionId: data.slice(8, 20),
    attributes: [],
  };

  let offset = 20;
  while (offset + 4 <= data.length) {
    const attrType = readUint16BE(data, offset);
    const attrLength = readUint16BE(data, offset + 2);
    offset += 4;
    if (offset + attrLength > data.length) {
      break;
    }
    packet.attributes.push({
      attrType,
      value: data.slice(offset, offset + attrLength),
    });
    offset += attrLength;
    while (offset % 4 !== 0) {
      offset += 1;
    }
  }

  return packet;
};

/**
 * Compute the RTP header length including CSRCs and extension header.
 * Needed to find the boundary between RTP header (clear) and SRTP payload (encrypted).
 */
export const getRtpHeaderLength = (data: Uint8Array): number => {
  if (data.length < 12) {
    throw new Error("RTP packet too short");
  }
  const cc = data[0]! & 0x0f;
  const hasExtension = (data[0]! & 0x10) !== 0;
  let offset = 12 + cc * 4;
  if (offset > data.length) {
    throw new Error("RTP packet truncated in CSRC list");
  }
  if (hasExtension) {
    if (offset + 4 > data.length) {
      throw new Error("RTP extension header truncated");
    }
    const extensionWords = readUint16BE(data, offset + 2);
    offset += 4 + extensionWords * 4;
  }
  if (offset > data.length) {
    throw new Error("RTP packet truncated after extension");
  }
  return offset;
};

/**
 * Parse a full RTP packet: payload type, marker, seq, timestamp, SSRC, CSRCs, extension, payload.
 * Used by the RTP receive engine and diagnostics to inspect inbound media packets.
 */
export const parseRtp = (data: Uint8Array): RtpPacket => {
  const hasExtension = (data[0]! & 0x10) !== 0;
  const cc = data[0]! & 0x0f;
  const csrcs: number[] = [];
  let offset = 12;
  if (offset > data.length) {
    throw new Error("RTP packet too short");
  }
  for (let index = 0; index < cc; index += 1) {
    if (offset + 4 > data.length) {
      throw new Error("RTP packet truncated in CSRC list");
    }
    csrcs.push(readUint32BE(data, offset));
    offset += 4;
  }
  let extensionProfile: number | null = null;
  let extensionData: Uint8Array | null = null;
  if (hasExtension) {
    if (offset + 4 > data.length) {
      throw new Error("RTP extension header truncated");
    }
    extensionProfile = readUint16BE(data, offset);
    const extensionWords = readUint16BE(data, offset + 2);
    const extensionLength = extensionWords * 4;
    offset += 4;
    if (offset + extensionLength > data.length) {
      throw new Error("RTP packet truncated after extension");
    }
    extensionData = data.slice(offset, offset + extensionLength);
    offset += extensionLength;
  }
  const headerLength = offset;
  return {
    payloadType: data[1]! & 0x7f,
    marker: (data[1]! & 0x80) !== 0,
    sequenceNumber: readUint16BE(data, 2),
    timestamp: readUint32BE(data, 4),
    ssrc: readUint32BE(data, 8),
    csrcs,
    hasExtension,
    extensionProfile,
    extensionData,
    headerLength,
    payload: data.slice(headerLength),
  };
};

/** Parse an RTCP packet header: count, packet type, length in 32-bit words. */
export const parseRtcp = (data: Uint8Array): RtcpPacket => {
  if (data.length < 4) {
    throw new Error("RTCP packet too short");
  }
  return {
    count: data[0]! & 0x1f,
    packetType: data[1]!,
    lengthWords: readUint16BE(data, 2),
    body: data.slice(4),
  };
};

/** Parse a DTLS record header: content type, version, epoch, sequence number. */
export const parseDtls = (data: Uint8Array): DtlsRecord => {
  if (data.length < 13) {
    throw new Error("DTLS record too short");
  }
  let sequenceNumber = 0n;
  for (let index = 5; index < 11; index += 1) {
    sequenceNumber = (sequenceNumber << 8n) | BigInt(data[index]!);
  }
  return {
    contentType: data[0]!,
    versionMajor: data[1]!,
    versionMinor: data[2]!,
    epoch: readUint16BE(data, 3),
    sequenceNumber,
    length: readUint16BE(data, 11),
  };
};

/**
 * Parse a UDP datagram: classify it, then parse headers into a structured form.
 * This is the single entry point that all relay/media handlers call.
 */
export const parseDatagram = (
  payload: Uint8Array,
  sourceHost = "",
  sourcePort = 0
): DatagramInfo => {
  const info: DatagramInfo = {
    kind: classifyPacket(payload),
    raw: payload,
    sourceHost,
    sourcePort,
  };

  switch (info.kind) {
    case "stun":
      info.stun = parseStun(payload);
      break;
    case "dtls":
      info.dtls = parseDtls(payload);
      break;
    case "rtp":
      info.rtp = parseRtp(payload);
      break;
    case "rtcp":
      info.rtcp = parseRtcp(payload);
      break;
    default:
      break;
  }

  return info;
};

export interface BuildRtpPacketOptions {
  payloadType?: number;
  sequenceNumber: number;
  timestamp: number;
  ssrc: number;
  marker?: number;
  extensionProfile?: number;
  extensionData?: Uint8Array;
  payload: Uint8Array;
}

/**
 * Build a raw RTP packet with optional WARP extension.
 * Used by RtpSendEngine to frame cleartext Opus payloads before SRTP protection.
 */
export const buildRtpPacket = ({
  payloadType = 111,
  sequenceNumber,
  timestamp,
  ssrc,
  marker = 0,
  extensionProfile,
  extensionData,
  payload,
}: BuildRtpPacketOptions): Uint8Array => {
  const normalizedExtensionData = extensionData ?? new Uint8Array(0);
  const extensionPadLength =
    extensionProfile === undefined
      ? 0
      : (4 - (normalizedExtensionData.length % 4)) % 4;
  const paddedExtensionData =
    extensionProfile === undefined
      ? new Uint8Array(0)
      : normalizedExtensionData.length === 0 && extensionPadLength === 0
        ? normalizedExtensionData
        : new Uint8Array(normalizedExtensionData.length + extensionPadLength);
  if (extensionProfile !== undefined && normalizedExtensionData.length > 0) {
    paddedExtensionData.set(normalizedExtensionData, 0);
  }

  const headerLength =
    12 + (extensionProfile === undefined ? 0 : 4 + paddedExtensionData.length);
  const header = new Uint8Array(headerLength);
  header[0] = 0x80 | (extensionProfile === undefined ? 0 : 0x10);
  header[1] = ((marker & 0x01) << 7) | (payloadType & 0x7f);
  writeUint16BE(header, 2, sequenceNumber & 0xffff);
  writeUint32BE(header, 4, timestamp >>> 0);
  writeUint32BE(header, 8, ssrc >>> 0);
  if (extensionProfile !== undefined) {
    writeUint16BE(header, 12, extensionProfile & 0xffff);
    writeUint16BE(header, 14, paddedExtensionData.length / 4);
    header.set(paddedExtensionData, 16);
  }
  const packet = new Uint8Array(header.length + payload.length);
  packet.set(header, 0);
  packet.set(payload, header.length);
  return packet;
};

export const buildRtcpSenderReport = ({
  ssrc,
  ntpMost = 0,
  ntpLeast = 0,
  rtpTimestamp = 0,
  packetCount = 0,
  octetCount = 0,
}: {
  ssrc: number;
  ntpMost?: number;
  ntpLeast?: number;
  rtpTimestamp?: number;
  packetCount?: number;
  octetCount?: number;
}): Uint8Array => {
  const packet = new Uint8Array(28);
  packet[0] = 0x80;
  packet[1] = 200;
  writeUint16BE(packet, 2, 6);
  writeUint32BE(packet, 4, ssrc >>> 0);
  writeUint32BE(packet, 8, ntpMost >>> 0);
  writeUint32BE(packet, 12, ntpLeast >>> 0);
  writeUint32BE(packet, 16, rtpTimestamp >>> 0);
  writeUint32BE(packet, 20, packetCount >>> 0);
  writeUint32BE(packet, 24, octetCount >>> 0);
  return packet;
};

export const buildRtcpSourceDescription = ({
  ssrc,
  cname,
}: {
  ssrc: number;
  cname: string;
}): Uint8Array => {
  const cnameBytes = new Uint8Array(Buffer.from(cname, "utf8"));
  const bodyBase = new Uint8Array(4 + 2 + cnameBytes.length + 1);
  writeUint32BE(bodyBase, 0, ssrc >>> 0);
  bodyBase[4] = 1;
  bodyBase[5] = cnameBytes.length & 0xff;
  bodyBase.set(cnameBytes, 6);
  bodyBase[6 + cnameBytes.length] = 0;
  const padLength = (4 - (bodyBase.length % 4)) % 4;
  const body =
    padLength === 0
      ? bodyBase
      : (() => {
          const padded = new Uint8Array(bodyBase.length + padLength);
          padded.set(bodyBase, 0);
          return padded;
        })();
  const packet = new Uint8Array(4 + body.length);
  packet[0] = 0x81;
  packet[1] = 202;
  writeUint16BE(packet, 2, packet.length / 4 - 1);
  packet.set(body, 4);
  return packet;
};

/**
 * WhatsApp WARP transport-feedback RTCP packet (proprietary PT 208, "TFB").
 *
 * Captured from the working WhatsApp Web WASM caller: the cleartext is an
 * 8-byte RTCP common header (`V=2, RC=1, PT=208, length=2 words`) followed by
 * a single 32-bit body word carrying the sender's current WARP RTP index
 * (a.k.a. `HBH_SRTP_RTP_Index`). The native client emits one of these per
 * outbound RTP packet to keep the relay's hop-by-hop stream context in sync
 * (strings: "HBH_SRTP_RTP_Index signaling probe", "build afb_srtp stream …
 * rtp_index …"). The packet is SRTCP-protected by the caller before sending.
 *
 * Wire shape (pre-SRTCP):
 *   [0]      0x81  (V=2, P=0, RC=1)
 *   [1]      208
 *   [2..3]   length = 2 (words - 1)
 *   [4..7]   sender SSRC
 *   [8..11]  WARP rtp_index (BE32)
 */
export const buildWarpTransportFeedback = ({
  ssrc,
  rtpIndex,
}: {
  ssrc: number;
  rtpIndex: number;
}): Uint8Array => {
  const packet = new Uint8Array(12);
  packet[0] = 0x81;
  packet[1] = 208;
  writeUint16BE(packet, 2, packet.length / 4 - 1);
  writeUint32BE(packet, 4, ssrc >>> 0);
  writeUint32BE(packet, 8, rtpIndex >>> 0);
  return packet;
};

/**
 * WhatsApp WARP "hello"/keepalive RTCP packet (proprietary PT 209).
 *
 * Captured cleartext is header-only: 8 bytes, `V=2, RC=1, PT=209, length=1`,
 * with no body beyond the SSRC. The native client emits this once near the
 * start of the media flow (right after SDES + the first TFB) to register the
 * stream with the relay. SRTCP-protected by the caller before sending.
 *
 * Wire shape (pre-SRTCP):
 *   [0]      0x81  (V=2, P=0, RC=1)
 *   [1]      209
 *   [2..3]   length = 1 (words - 1)
 *   [4..7]   sender SSRC
 */
export const buildWarpStreamHello = ({
  ssrc,
}: {
  ssrc: number;
}): Uint8Array => {
  const packet = new Uint8Array(8);
  packet[0] = 0x81;
  packet[1] = 209;
  writeUint16BE(packet, 2, packet.length / 4 - 1);
  writeUint32BE(packet, 4, ssrc >>> 0);
  return packet;
};

/**
 * WhatsApp WARP application-layer feedback (RFC 4585 PSFB, PT 206, FMT=15).
 *
 * Captured cleartext is 20 bytes: an 8-byte RTCP FB common header
 * (`V=2, FMT=15, PT=206, length=4 words`) carrying the packet-sender SSRC,
 * followed by a 12-byte FCI (the media-source SSRC plus an 8-byte
 * application-defined payload — WhatsApp's "AFB" body). We reproduce the
 * exact header + FCI framing the relay expects; the AFB body defaults to the
 * media SSRC echo + zeros, matching the observed length. SRTCP-protected by
 * the caller before sending.
 *
 * Wire shape (pre-SRTCP):
 *   [0]       0x8f  (V=2, P=0, FMT=15)
 *   [1]       206
 *   [2..3]    length = 4 (words - 1)
 *   [4..7]    packet-sender SSRC
 *   [8..11]   media-source SSRC
 *   [12..19]  AFB application data (8 bytes)
 */
export const buildWarpApplicationFeedback = ({
  ssrc,
  mediaSsrc,
  appData,
}: {
  ssrc: number;
  mediaSsrc?: number;
  appData?: Uint8Array;
}): Uint8Array => {
  const packet = new Uint8Array(20);
  packet[0] = 0x8f;
  packet[1] = 206;
  writeUint16BE(packet, 2, packet.length / 4 - 1);
  writeUint32BE(packet, 4, ssrc >>> 0);
  writeUint32BE(packet, 8, (mediaSsrc ?? ssrc) >>> 0);
  if (appData && appData.length > 0) {
    packet.set(appData.subarray(0, 8), 12);
  }
  return packet;
};

const parseIpBytes = (host: string): { family: number; bytes: Uint8Array } => {
  if (host.includes(":")) {
    const parts = host.split("::");
    const left = parts[0] ? parts[0].split(":").filter(Boolean) : [];
    const right = parts[1] ? parts[1].split(":").filter(Boolean) : [];
    const missing = 8 - (left.length + right.length);
    const expanded = [
      ...left,
      ...new Array(Math.max(0, missing)).fill("0"),
      ...right,
    ];
    const bytes = new Uint8Array(16);
    expanded.forEach((piece, index) => {
      const value = Number.parseInt(piece || "0", 16) & 0xffff;
      bytes[index * 2] = (value >>> 8) & 0xff;
      bytes[index * 2 + 1] = value & 0xff;
    });
    return { family: 0x02, bytes };
  }

  const octets = host.split(".").map((part) => Number.parseInt(part, 10) & 0xff);
  if (octets.length !== 4) {
    throw new Error(`invalid IPv4 address: ${host}`);
  }
  return { family: 0x01, bytes: new Uint8Array(octets) };
};

export const xorAddressBytes = (
  host: string,
  port: number,
  transactionId: Uint8Array
): Uint8Array => {
  const parsed = parseIpBytes(host);
  const result = new Uint8Array(4 + parsed.bytes.length);
  result[1] = parsed.family;
  const xPort = (port & 0xffff) ^ (StunMagicCookie >>> 16);
  writeUint16BE(result, 2, xPort);

  const cookie = uint32ToBytes(StunMagicCookie);
  for (let index = 0; index < parsed.bytes.length; index += 1) {
    const mask =
      index < 4 ? cookie[index]! : transactionId[index - 4] ?? 0;
    result[4 + index] = parsed.bytes[index]! ^ mask;
  }
  return result;
};

export const decodeXorAddress = (
  value: Uint8Array,
  transactionId: Uint8Array
): { host: string; port: number } => {
  if (value.length < 4) {
    throw new Error("XOR address attribute too short");
  }
  const family = value[1]!;
  const port = readUint16BE(value, 2) ^ (StunMagicCookie >>> 16);
  const cookie = uint32ToBytes(StunMagicCookie);
  const decoded = new Uint8Array(value.length - 4);
  for (let index = 0; index < decoded.length; index += 1) {
    const mask = index < 4 ? cookie[index]! : transactionId[index - 4] ?? 0;
    decoded[index] = value[4 + index]! ^ mask;
  }

  if (family === 0x01) {
    return {
      host: Array.from(decoded.values()).join("."),
      port,
    };
  }

  if (family === 0x02 && decoded.length === 16) {
    const groups: string[] = [];
    for (let index = 0; index < 16; index += 2) {
      groups.push(((decoded[index]! << 8) | decoded[index + 1]!).toString(16));
    }
    return {
      host: groups.join(":"),
      port,
    };
  }

  throw new Error("unknown XOR address family");
};
