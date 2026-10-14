/**
 * ============================================================================
 * STACK LAYER 1 — Relay transport (production)
 * ============================================================================
 *
 * Carries raw relay bytes to/from WhatsApp's relay servers over WebRTC
 * DataChannels using @roamhq/wrtc. Opens one peer connection per relay
 * endpoint, mirrors the browser's ICE/DTLS handshake, and surfaces inbound
 * datagrams plus ICE RTT to the engine.
 *
 * Why: production WhatsApp Web reaches relays via WebRTC, not bare UDP; matching
 * that path keeps NAT traversal and relay acceptance identical to the official
 * client. Hands off: inbound bytes -> protocol/feedRelayDatagram; outbound bytes
 * come from the SRTP/STUN layers via the engine's relaySend callback.
 */
/**
 * WebRTC-based relay transport for WhatsApp VoIP.
 *
 * RelayRtcTransport manages SCTP DataChannels over DTLS to WhatsApp's relay
 * servers using @roamhq/wrtc. It consumes the parsed relay-list update from
 * signaling, establishes per-relay pre-negotiated data channels, and forwards
 * media/STUN datagrams transparently. This is the transport layer that sits
 * between the engine's relay send callback and the actual UDP socket — the
 * WhatsApp relay only accepts DTLS-tunneled traffic, not raw UDP.
 */

import { appendFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const LIB_DIR = dirname(fileURLToPath(import.meta.url));
const NODE_LOAD_DIR = resolve(LIB_DIR, "../..");
const WORKSPACE_DIR = resolve(NODE_LOAD_DIR, "..");
const WASM_LOAD_DIR = resolve(WORKSPACE_DIR, "wasm-load");
const WRTC_RESOLVE_PATHS = [
  NODE_LOAD_DIR,
  WORKSPACE_DIR,
  WASM_LOAD_DIR,
  process.cwd(),
];

const RELAY_PROTO_UDP = 0;
const FAUX_WEB_CLIENT_RELAY_PORT = 3478;
const TRUE_WEB_CLIENT_RELAY_PORT = 3480;
const CONNECTION_TIMEOUT_MS = 20_000;
const ICE_RESTART_IDLE_THRESHOLD_MS = 10_000;
const ICE_RTT_POLL_MS = 1_000;
const MAX_BUFFER_SIZE = 256 * 1024;
const RELAY_PACKET_LOG_PATH = process.env.CALL_DUMP_RELAY_PACKETS_PATH || "";
const DISABLE_IPV6 = process.env.CALL_DISABLE_IPV6 !== "0";
const RELAY_PORT_MODE =
  process.env.CALL_RELAY_PORT_MODE === "web" ? "web" : "original";
const USE_ORIGINAL_RELAY_PORTS = RELAY_PORT_MODE === "original";
const RELAY_DTLS_FINGERPRINT =
  "F9:CA:0C:98:A3:CC:71:D6:42:CE:5A:E2:53:D2:15:20:D3:1B:BA:D8:57:A4:F0:AF:BE:0B:FB:F3:6B:0C:A0:68";

type RelayAddress = {
  protocol: number;
  ipv4?: string;
  ipv6?: string;
  port?: number;
  port_v6?: number;
};

type RelayDescriptor = {
  relay_id: number;
  relay_name: string;
  token_id: number;
  auth_token_id?: number;
  addresses: RelayAddress[];
};

export type RelayListUpdatePayload = {
  relay_key: string;
  relay_tokens: string[];
  auth_tokens?: string[];
  enable_edgeray_dtls_active_mode?: boolean;
  relays: RelayDescriptor[];
};

type RelayConnectionInfo = {
  id: string;
  relayId: number;
  ip: string;
  port: number;
  originalPort: number;
  isIPv6: boolean;
  token: string;
  authToken?: string;
  key: string;
  name: string;
  enableEdgerayDtlsActiveMode: boolean;
};

type RelayConnectionState =
  | "none"
  | "connecting"
  | "open"
  | "closed"
  | "failed";

type RelayConnectionRuntime = {
  info: RelayConnectionInfo;
  state: RelayConnectionState;
  peerConnection: any | null;
  dataChannel: any | null;
  iceCandidate: string | null;
  packetBuffer: ArrayBuffer[];
  bufferedBytes: number;
  connectPromise: Promise<void> | null;
  connectionTimeout: NodeJS.Timeout | null;
  iceStatsInterval: NodeJS.Timeout | null;
  lastIceRttMs: number | null;
  hasReceivedFirstPacket: boolean;
  hasNonStunPacketSent: boolean;
  sentMedia: boolean;
  lastRxPacketTime: number;
  isReconnecting: boolean;
  stats: RelayTransportStats;
};

type RelayPacketKind = "stun_alloc" | "stun_bind" | "stun_unknown" | "non_stun";

export type RelayTransportStats = {
  sentPackets: number;
  receivedPackets: number;
  sentBytes: number;
  receivedBytes: number;
  droppedPackets: number;
  openConnections: number;
};

type RelayTransportConfig = {
  onTransportMessage: (data: Uint8Array, ip: string, port: number) => void;
  onIceRtt?: (rttMs: number, ip: string, port: number) => void;
  onLog?: (
    level: "log" | "warn" | "error",
    message: string,
    details?: Record<string, unknown>,
  ) => void;
};

const getConnectionIdentifier = (ip: string, port: number) =>
  ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`;

const createEmptyStats = (): RelayTransportStats => ({
  sentPackets: 0,
  receivedPackets: 0,
  sentBytes: 0,
  receivedBytes: 0,
  droppedPackets: 0,
  openConnections: 0,
});

const getRelayLookupId = (ip: string, port: number) =>
  getConnectionIdentifier(
    ip,
    port === TRUE_WEB_CLIENT_RELAY_PORT ? TRUE_WEB_CLIENT_RELAY_PORT : port,
  );

const getRtcConnectPort = (info: RelayConnectionInfo) =>
  info.ip === "157.240.24.133" ? FAUX_WEB_CLIENT_RELAY_PORT : info.port;

const getVoipStackPort = (info: RelayConnectionInfo) => {
  if (USE_ORIGINAL_RELAY_PORTS) {
    return info.originalPort || info.port;
  }

  const sourcePort = info.originalPort || info.port;
  return sourcePort === TRUE_WEB_CLIENT_RELAY_PORT
    ? TRUE_WEB_CLIENT_RELAY_PORT
    : FAUX_WEB_CLIENT_RELAY_PORT;
};

const bufferPacket = (
  connection: RelayConnectionRuntime,
  packet: ArrayBuffer,
): boolean => {
  if (packet.byteLength > MAX_BUFFER_SIZE) {
    connection.stats.droppedPackets += 1;
    return false;
  }

  while (
    connection.packetBuffer.length > 0 &&
    connection.bufferedBytes + packet.byteLength > MAX_BUFFER_SIZE
  ) {
    const dropped = connection.packetBuffer.shift();
    if (dropped) {
      connection.bufferedBytes -= dropped.byteLength;
      connection.stats.droppedPackets += 1;
    }
  }

  connection.packetBuffer.push(packet);
  connection.bufferedBytes += packet.byteLength;
  return true;
};

const shiftPacket = (
  connection: RelayConnectionRuntime,
): ArrayBuffer | null => {
  const packet = connection.packetBuffer.shift() || null;
  if (packet) {
    connection.bufferedBytes -= packet.byteLength;
  }
  return packet;
};

const replaceIceCredentials = (sdp: string, ufrag: string, pwd: string) =>
  sdp
    .replace(/a=ice-ufrag:[^\r\n]+/g, `a=ice-ufrag:${ufrag}`)
    .replace(/a=ice-pwd:[^\r\n]+/g, `a=ice-pwd:${pwd}`);

const replaceDtlsFingerprint = (
  sdp: string,
  algorithm: string,
  fingerprint: string,
) =>
  sdp.replace(
    /a=fingerprint:[^\r\n]+/g,
    `a=fingerprint:${algorithm} ${fingerprint}`,
  );

const removeIceCandidates = (sdp: string) =>
  sdp
    .replace(/a=candidate:[^\r\n]+\r?\n/g, "")
    .replace(/a=end-of-candidates\r?\n?/g, "");

const appendRelayCandidate = (sdp: string, ip: string, port: number) => {
  const candidate = `a=candidate:2 1 udp 2122262783 ${ip} ${port} typ host generation 0 network-cost 5`;
  return `${removeIceCandidates(sdp)}${candidate}\r\na=end-of-candidates\r\n`;
};

const buildRemoteRelayAnswer = (
  offerSdp: string,
  info: RelayConnectionInfo,
) => {
  const setupLine = info.enableEdgerayDtlsActiveMode
    ? "a=setup:active"
    : "a=setup:passive";
  let answerSdp = offerSdp.replace(/a=setup:actpass/g, setupLine);
  answerSdp = replaceIceCredentials(
    answerSdp,
    info.authToken || info.token,
    info.key,
  );
  answerSdp = replaceDtlsFingerprint(
    answerSdp,
    "sha-256",
    RELAY_DTLS_FINGERPRINT,
  );
  answerSdp = answerSdp.replace(/a=ice-options:[^\r\n]+\r\n/g, "");
  answerSdp = answerSdp.replace(
    /a=max-message-size:[^\r\n]+/g,
    "a=max-message-size:1200",
  );
  return appendRelayCandidate(answerSdp, info.ip, info.port);
};

const toArrayBuffer = (data: Uint8Array | Buffer): ArrayBuffer => {
  const copy = new Uint8Array(data.byteLength);
  copy.set(data);
  return copy.buffer;
};

const toUint8Array = (data: unknown): Uint8Array | null => {
  if (data instanceof Uint8Array) {
    return new Uint8Array(data);
  }
  if (Buffer.isBuffer(data)) {
    return new Uint8Array(data);
  }
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data);
  }
  if (
    data &&
    typeof data === "object" &&
    "byteLength" in data &&
    "buffer" in data
  ) {
    const view = data as ArrayBufferView;
    return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  }
  return null;
};

const classifyRelayPacket = (packet: ArrayBuffer): RelayPacketKind => {
  if (packet.byteLength < 2) {
    return "non_stun";
  }

  const bytes = new Uint8Array(packet);
  const first = bytes[0]!;
  const second = bytes[1]!;
  if ((first & 0xc0) !== 0) {
    return "non_stun";
  }

  const stunType = ((first & 0x3f) << 8) | second;
  if (stunType === 0x0001) {
    return "stun_bind";
  }
  if (stunType === 0x0003) {
    return "stun_alloc";
  }
  return "stun_unknown";
};

const appendRelayPacketLog = (
  direction: "send" | "recv",
  connection: RelayConnectionRuntime,
  packet: Uint8Array | ArrayBuffer,
) => {
  if (!RELAY_PACKET_LOG_PATH) {
    return;
  }

  const buffer =
    packet instanceof ArrayBuffer
      ? Buffer.from(new Uint8Array(packet))
      : Buffer.from(packet.buffer, packet.byteOffset, packet.byteLength);

  appendFileSync(
    RELAY_PACKET_LOG_PATH,
    JSON.stringify({
      ts: new Date().toISOString(),
      direction,
      id: connection.info.id,
      relayId: connection.info.relayId,
      relayName: connection.info.name,
      ip: connection.info.ip,
      rtcPort: connection.info.port,
      voipPort: getVoipStackPort(connection.info),
      size: buffer.byteLength,
      hex: buffer.toString("hex"),
    }) + "\n",
  );
};

export class RelayRtcTransport {
  #relayInfoById = new Map<string, RelayConnectionInfo>();
  #connections = new Map<string, RelayConnectionRuntime>();
  #loggedIpv6Drops = new Set<string>();
  #totals = createEmptyStats();
  #wrtcPromise: Promise<any> | null = null;

  constructor(private readonly config: RelayTransportConfig) {}

  updateRelayList(update: RelayListUpdatePayload) {
    const nextInfoById = new Map<string, RelayConnectionInfo>();

    for (const relay of update.relays || []) {
      if (
        relay.token_id == null ||
        relay.token_id < 0 ||
        relay.token_id >= (update.relay_tokens || []).length
      ) {
        this.#log("warn", "skipping relay with invalid token_id", {
          relayId: relay.relay_id,
          tokenId: relay.token_id,
        });
        continue;
      }

      const authToken =
        update.auth_tokens &&
        relay.auth_token_id != null &&
        relay.auth_token_id >= 0
          ? update.auth_tokens[relay.auth_token_id]
          : undefined;

      for (const address of relay.addresses || []) {
        if (address.protocol !== RELAY_PROTO_UDP) continue;

        if (address.ipv4 && address.port != null) {
          const clientPort = USE_ORIGINAL_RELAY_PORTS
            ? address.port
            : TRUE_WEB_CLIENT_RELAY_PORT;
          const id = getConnectionIdentifier(address.ipv4, clientPort);
          nextInfoById.set(id, {
            id,
            relayId: relay.relay_id,
            ip: address.ipv4,
            port: clientPort,
            originalPort: address.port,
            isIPv6: false,
            token: update.relay_tokens[relay.token_id]!,
            authToken,
            key: update.relay_key,
            name: relay.relay_name,
            enableEdgerayDtlsActiveMode:
              update.enable_edgeray_dtls_active_mode === true,
          });
        }

        if (!DISABLE_IPV6 && address.ipv6 && address.port_v6 != null) {
          const clientPort = USE_ORIGINAL_RELAY_PORTS
            ? address.port_v6
            : TRUE_WEB_CLIENT_RELAY_PORT;
          const id = getConnectionIdentifier(address.ipv6, clientPort);
          nextInfoById.set(id, {
            id,
            relayId: relay.relay_id,
            ip: address.ipv6,
            port: clientPort,
            originalPort: address.port_v6,
            isIPv6: true,
            token: update.relay_tokens[relay.token_id]!,
            authToken,
            key: update.relay_key,
            name: relay.relay_name,
            enableEdgerayDtlsActiveMode:
              update.enable_edgeray_dtls_active_mode === true,
          });
        }
      }
    }

    for (const id of this.#relayInfoById.keys()) {
      if (!nextInfoById.has(id)) this.#closeConnection(id, "relay_removed");
    }

    this.#relayInfoById.clear();
    for (const [id, info] of nextInfoById) {
      this.#relayInfoById.set(id, info);
      void this.#ensureConnection(info);
    }

    this.#log("log", "updated relay RTC transport map", {
      relayCount: nextInfoById.size,
      ipv6Disabled: DISABLE_IPV6,
      relayPortMode: RELAY_PORT_MODE,
    });
  }

  send(packet: Uint8Array | Buffer, ip: string, port: number): number {
    const requestedId = getConnectionIdentifier(ip, port);
    const preferredPort = USE_ORIGINAL_RELAY_PORTS
      ? port
      : TRUE_WEB_CLIENT_RELAY_PORT;
    let info: RelayConnectionInfo | undefined;
    const candidateIds = [
      requestedId,
      getConnectionIdentifier(ip, preferredPort),
      getRelayLookupId(ip, TRUE_WEB_CLIENT_RELAY_PORT),
      getRelayLookupId(ip, FAUX_WEB_CLIENT_RELAY_PORT),
    ];
    for (const candidateId of candidateIds) {
      info = this.#relayInfoById.get(candidateId);
      if (info) {
        break;
      }
    }
    if (!info) {
      if (DISABLE_IPV6 && ip.includes(":")) {
        if (!this.#loggedIpv6Drops.has(requestedId)) {
          this.#loggedIpv6Drops.add(requestedId);
          this.#log(
            "warn",
            "dropping ipv6 relay packet because ipv6 is disabled and no ipv4 alias exists",
            {
              ip,
              port,
              requestedId,
            },
          );
        }
        return 0;
      }
      const earlyConnection = this.#getOrCreateEarlyConnection(ip, port);
      bufferPacket(earlyConnection, toArrayBuffer(packet));
      this.#log(
        "warn",
        "buffering early relay packet until relay info arrives",
        {
          ip,
          port,
          requestedId,
          size: packet.byteLength,
        },
      );
      return packet.byteLength;
    }

    const connection = this.#getOrCreateConnection(info);
    const arrayBuffer = toArrayBuffer(packet);
    if (
      classifyRelayPacket(arrayBuffer) === "stun_alloc" &&
      connection.state === "open" &&
      connection.sentMedia &&
      Date.now() - connection.lastRxPacketTime > ICE_RESTART_IDLE_THRESHOLD_MS
    ) {
      this.#log(
        "warn",
        "relay RTC STUN alloc on stale open connection, restarting ICE",
        {
          id: connection.info.id,
          idleMs: Date.now() - connection.lastRxPacketTime,
        },
      );
      connection.packetBuffer = [];
      connection.bufferedBytes = 0;
      bufferPacket(connection, arrayBuffer);
      void this.#restartIce(connection);
      return packet.byteLength;
    }

    if (
      connection.state === "open" &&
      connection.dataChannel?.readyState === "open"
    ) {
      if (!this.#sendBufferedPacket(connection, arrayBuffer)) {
        connection.stats.droppedPackets += 1;
      }
      return packet.byteLength;
    }

    bufferPacket(connection, arrayBuffer);
    void this.#ensureConnection(info);
    return packet.byteLength;
  }

  /**
   * List the relays node-load is connected to, with their name, the relay's
   * VoIP/original UDP IP+port, and the last measured ICE RTT (ms). Used to
   * build the `<relaylatency>` signaling the peer needs to converge on a
   * common relay (without it the receiver never reaches RelayCreateSuccess).
   * Only relays with an open datachannel are returned.
   */
  listRelayLatencies(): {
    name: string;
    ip: string;
    port: number;
    rttMs: number | null;
    open: boolean;
  }[] {
    const out: {
      name: string;
      ip: string;
      port: number;
      rttMs: number | null;
      open: boolean;
    }[] = [];
    for (const connection of this.#connections.values()) {
      const info = connection.info;
      if (info.isIPv6) {
        continue;
      }
      const open =
        connection.state === "open" &&
        connection.dataChannel?.readyState === "open";
      out.push({
        name: info.name,
        ip: info.ip,
        // The relay's true UDP port (what the peer/server keys on), not the
        // local client-port remap.
        port: info.originalPort ?? info.port,
        rttMs: connection.lastIceRttMs,
        open,
      });
    }
    return out;
  }

  getStats(): RelayTransportStats {
    let openConnections = 0;
    for (const connection of this.#connections.values()) {
      if (connection.state === "open") {
        openConnections += 1;
      }
    }

    return {
      ...this.#totals,
      openConnections,
    };
  }

  async closeAll() {
    for (const id of [...this.#connections.keys()]) {
      this.#closeConnection(id, "close_all");
    }
  }

  #getOrCreateConnection(
    info: RelayConnectionInfo,
  ): RelayConnectionRuntime {
    const existing = this.#connections.get(info.id);
    if (existing) {
      existing.info = info;
      return existing;
    }

    const created: RelayConnectionRuntime = {
      info,
      state: "none",
      peerConnection: null,
      dataChannel: null,
      iceCandidate: null,
      packetBuffer: [],
      bufferedBytes: 0,
      connectPromise: null,
      connectionTimeout: null,
      iceStatsInterval: null,
      lastIceRttMs: null,
      hasReceivedFirstPacket: false,
      hasNonStunPacketSent: false,
      sentMedia: false,
      lastRxPacketTime: 0,
      isReconnecting: false,
      stats: createEmptyStats(),
    };
    this.#connections.set(info.id, created);
    return created;
  }

  #getOrCreateEarlyConnection(
    ip: string,
    port: number,
  ): RelayConnectionRuntime {
    const id = getConnectionIdentifier(ip, port);
    const existing = this.#connections.get(id);
    if (existing) {
      return existing;
    }

    const placeholderInfo: RelayConnectionInfo = {
      id,
      relayId: 0,
      ip,
      port,
      originalPort: port,
      isIPv6: ip.includes(":"),
      token: "",
      key: "",
      name: "early-packet",
      enableEdgerayDtlsActiveMode: false,
    };
    const created: RelayConnectionRuntime = {
      info: placeholderInfo,
      state: "none",
      peerConnection: null,
      dataChannel: null,
      iceCandidate: null,
      packetBuffer: [],
      bufferedBytes: 0,
      connectPromise: null,
      connectionTimeout: null,
      iceStatsInterval: null,
      lastIceRttMs: null,
      hasReceivedFirstPacket: false,
      hasNonStunPacketSent: false,
      sentMedia: false,
      lastRxPacketTime: 0,
      isReconnecting: false,
      stats: createEmptyStats(),
    };
    this.#connections.set(id, created);
    return created;
  }

  async #ensureConnection(info: RelayConnectionInfo) {
    const connection = this.#getOrCreateConnection(info);
    if (connection.state === "open" || connection.state === "connecting") {
      return connection.connectPromise || Promise.resolve();
    }

    const promise = this.#connect(connection);
    connection.connectPromise = promise;
    try {
      await promise;
    } finally {
      connection.connectPromise = null;
    }
  }

  async #connect(connection: RelayConnectionRuntime) {
    const wrtcModule = await this.#loadWrtc();
    const RTCPeerConnection = wrtcModule.RTCPeerConnection;
    if (typeof RTCPeerConnection !== "function") {
      throw new Error("RTCPeerConnection unavailable from @roamhq/wrtc");
    }

    this.#closePeerObjects(connection);
    connection.state = "connecting";

    const pc = new RTCPeerConnection();
    const dc = pc.createDataChannel("pre-negotiated", {
      negotiated: true,
      id: 0,
      ordered: false,
      maxRetransmits: 0,
      priority: "high",
    });

    connection.peerConnection = pc;
    connection.dataChannel = dc;
    dc.binaryType = "arraybuffer";

    dc.onopen = () => {
      connection.state = "open";
      connection.isReconnecting = false;
      this.#log("log", "relay RTC data channel open", {
        id: connection.info.id,
        relay: connection.info.name,
      });
      if (connection.connectionTimeout) {
        clearTimeout(connection.connectionTimeout);
        connection.connectionTimeout = null;
      }
      this.#flushBufferedPackets(connection);
      this.#startIceRttPolling(connection);
    };

    dc.onclose = () => {
      if (connection.state !== "failed") {
        connection.state = "closed";
      }
      this.#log("warn", "relay RTC data channel closed", {
        id: connection.info.id,
        relay: connection.info.name,
      });
    };

    dc.onerror = (event: unknown) => {
      connection.state = "failed";
      this.#log("error", "relay RTC data channel error", {
        id: connection.info.id,
        relay: connection.info.name,
        event: String(event),
      });
    };

    dc.onmessage = (event: { data: unknown }) => {
      const packet = toUint8Array(event.data);
      if (!packet) {
        this.#log("warn", "dropping relay RTC payload with unsupported type", {
          id: connection.info.id,
          type: typeof event.data,
        });
        return;
      }

      connection.stats.receivedPackets += 1;
      connection.stats.receivedBytes += packet.byteLength;
      connection.hasReceivedFirstPacket = true;
      connection.lastRxPacketTime = Date.now();
      this.#totals.receivedPackets += 1;
      this.#totals.receivedBytes += packet.byteLength;
      appendRelayPacketLog("recv", connection, packet);
      this.config.onTransportMessage(
        packet,
        connection.info.ip,
        getVoipStackPort(connection.info),
      );
    };

    pc.onicecandidate = (event: {
      candidate?: { candidate?: string } | null;
    }) => {
      if (event.candidate?.candidate && !connection.iceCandidate) {
        connection.iceCandidate = event.candidate.candidate;
      }
    };

    pc.oniceconnectionstatechange = () => {
      this.#log("log", "relay RTC ICE state changed", {
        id: connection.info.id,
        state: pc.iceConnectionState,
      });
      if (
        pc.iceConnectionState === "failed" ||
        pc.iceConnectionState === "closed"
      ) {
        connection.state = "failed";
      }
    };

    connection.connectionTimeout = setTimeout(() => {
      if (connection.state === "connecting") {
        connection.state = "failed";
        this.#log("warn", "relay RTC connection timed out", {
          id: connection.info.id,
          relay: connection.info.name,
        });
        this.#closePeerObjects(connection);
      }
    }, CONNECTION_TIMEOUT_MS);

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    const answerInfo = {
      ...connection.info,
      port: getRtcConnectPort(connection.info),
    };
    const remoteSdp = buildRemoteRelayAnswer(offer.sdp || "", answerInfo);
    await pc.setRemoteDescription({
      type: "answer",
      sdp: remoteSdp,
    });

    this.#log("log", "relay RTC SDP configured", {
      id: connection.info.id,
      relay: connection.info.name,
    });
    this.#log("log", "relay RTC credentials debug", {
      id: connection.info.id,
      tokenLen: connection.info.token?.length,
      tokenFirst20: connection.info.token?.substring(0, 20),
      authTokenLen: connection.info.authToken?.length,
      authTokenFirst20: connection.info.authToken?.substring(0, 20),
      keyLen: connection.info.key?.length,
      keyFirst20: connection.info.key?.substring(0, 20),
      iceUfrag: (answerInfo.authToken || answerInfo.token)?.substring(0, 30),
      icePwd: answerInfo.key?.substring(0, 30),
    });
  }

  async #restartIce(connection: RelayConnectionRuntime) {
    if (connection.isReconnecting) {
      return;
    }
    if (!connection.hasNonStunPacketSent) {
      this.#log(
        "warn",
        "relay RTC ICE restart skipped before media packets were sent",
        {
          id: connection.info.id,
        },
      );
      return;
    }

    const RTCPeerConnection = (await this.#loadWrtc()).RTCPeerConnection;
    if (typeof RTCPeerConnection !== "function") {
      return;
    }

    connection.isReconnecting = true;
    try {
      this.#closePeerObjects(connection);
      connection.state = "connecting";

      const pc = new RTCPeerConnection();
      const dc = pc.createDataChannel("pre-negotiated", {
        negotiated: true,
        id: 0,
        ordered: false,
        maxRetransmits: 0,
        priority: "high",
      });

      connection.peerConnection = pc;
      connection.dataChannel = dc;
      dc.binaryType = "arraybuffer";
      dc.onopen = () => {
        connection.state = "open";
        connection.isReconnecting = false;
        this.#flushBufferedPackets(connection);
        this.#startIceRttPolling(connection);
      };
      dc.onclose = () => {
        if (connection.state !== "failed") {
          connection.state = "closed";
        }
      };
      dc.onerror = () => {
        connection.state = "failed";
      };
      dc.onmessage = (event: { data: unknown }) => {
        const packet = toUint8Array(event.data);
        if (!packet) {
          return;
        }
        connection.stats.receivedPackets += 1;
        connection.stats.receivedBytes += packet.byteLength;
        connection.hasReceivedFirstPacket = true;
        connection.lastRxPacketTime = Date.now();
        this.#totals.receivedPackets += 1;
        this.#totals.receivedBytes += packet.byteLength;
        appendRelayPacketLog("recv", connection, packet);
        this.config.onTransportMessage(
          packet,
          connection.info.ip,
          getVoipStackPort(connection.info),
        );
      };
      pc.onicecandidate = (event: {
        candidate?: { candidate?: string } | null;
      }) => {
        if (event.candidate?.candidate && !connection.iceCandidate) {
          connection.iceCandidate = event.candidate.candidate;
        }
      };

      const offer = await pc.createOffer({ iceRestart: false });
      let localSdp = offer.sdp || "";
      if (connection.iceCandidate) {
        localSdp = `${removeIceCandidates(localSdp)}a=${connection.iceCandidate}\r\na=end-of-candidates\r\n`;
      }
      await pc.setLocalDescription({ type: "offer", sdp: localSdp });
      const remoteSdp = buildRemoteRelayAnswer(localSdp, {
        ...connection.info,
        port: getRtcConnectPort(connection.info),
      });
      await pc.setRemoteDescription({ type: "answer", sdp: remoteSdp });
    } catch (error) {
      connection.state = "failed";
      this.#log("warn", "relay RTC ICE restart failed", {
        id: connection.info.id,
        error: String(error),
      });
    } finally {
      connection.isReconnecting = false;
    }
  }

  #flushBufferedPackets(connection: RelayConnectionRuntime) {
    while (
      connection.state === "open" &&
      connection.dataChannel?.readyState === "open" &&
      connection.packetBuffer.length > 0
    ) {
      const packet = shiftPacket(connection);
      if (!packet) {
        break;
      }
      if (!this.#sendBufferedPacket(connection, packet)) {
        connection.stats.droppedPackets += 1;
        break;
      }
    }
  }

  #sendBufferedPacket(
    connection: RelayConnectionRuntime,
    packet: ArrayBuffer,
  ): boolean {
    try {
      connection.dataChannel?.send(packet);
      if (classifyRelayPacket(packet) === "non_stun") {
        connection.hasNonStunPacketSent = true;
        connection.sentMedia = true;
      }
      connection.stats.sentPackets += 1;
      connection.stats.sentBytes += packet.byteLength;
      this.#totals.sentPackets += 1;
      this.#totals.sentBytes += packet.byteLength;
      appendRelayPacketLog("send", connection, packet);
      return true;
    } catch (err) {
      this.#log("warn", "relay RTC send failed", {
        id: connection.info.id,
        relay: connection.info.name,
        error: String(err),
      });
      return false;
    }
  }

  #startIceRttPolling(connection: RelayConnectionRuntime) {
    this.#stopIceRttPolling(connection);

    const pc = connection.peerConnection;
    if (!pc || typeof pc.getStats !== "function" || !this.config.onIceRtt) {
      return;
    }

    const poll = async () => {
      const rttMs = await this.#readCurrentRoundTripTimeMs(pc);
      if (rttMs == null || connection.lastIceRttMs === rttMs) {
        return;
      }

      connection.lastIceRttMs = rttMs;
      this.config.onIceRtt?.(rttMs, connection.info.ip, connection.info.port);
    };

    void poll();
    connection.iceStatsInterval = setInterval(() => {
      void poll();
    }, ICE_RTT_POLL_MS);
    connection.iceStatsInterval.unref?.();
  }

  #stopIceRttPolling(connection: RelayConnectionRuntime) {
    if (connection.iceStatsInterval) {
      clearInterval(connection.iceStatsInterval);
      connection.iceStatsInterval = null;
    }

    connection.lastIceRttMs = null;
  }

  async #readCurrentRoundTripTimeMs(pc: any): Promise<number | null> {
    try {
      const stats = await pc.getStats();
      const reports =
        stats && typeof stats.values === "function"
          ? Array.from(stats.values())
          : Array.isArray(stats)
            ? stats
            : Object.values(stats || {});
      if (!reports.length) {
        return null;
      }

      let selectedCandidatePairId = "";
      for (const report of reports as any[]) {
        if (
          report?.type === "transport" &&
          typeof report.selectedCandidatePairId === "string"
        ) {
          selectedCandidatePairId = report.selectedCandidatePairId;
          break;
        }
      }

      const candidatePairs = (reports as any[]).filter(
        (report) => report?.type === "candidate-pair",
      );
      const selectedPair =
        (selectedCandidatePairId &&
          candidatePairs.find(
            (report) => report?.id === selectedCandidatePairId,
          )) ||
        candidatePairs.find(
          (report) => report?.selected || report?.nominated,
        ) ||
        candidatePairs[0];

      const rttSeconds =
        typeof selectedPair?.currentRoundTripTime === "number"
          ? selectedPair.currentRoundTripTime
          : typeof selectedPair?.totalRoundTripTime === "number" &&
              typeof selectedPair?.responsesReceived === "number" &&
              selectedPair.responsesReceived > 0
            ? selectedPair.totalRoundTripTime / selectedPair.responsesReceived
            : null;
      if (
        rttSeconds == null ||
        !Number.isFinite(rttSeconds) ||
        rttSeconds <= 0
      ) {
        return null;
      }

      return Math.max(1, Math.round(rttSeconds * 1000));
    } catch {
      return null;
    }
  }

  #closeConnection(id: string, reason: string) {
    const connection = this.#connections.get(id);
    if (!connection) {
      return;
    }

    this.#log("log", "closing relay RTC connection", { id, reason });
    if (connection.connectionTimeout) {
      clearTimeout(connection.connectionTimeout);
      connection.connectionTimeout = null;
    }
    this.#closePeerObjects(connection);
    connection.state = "closed";
    connection.packetBuffer = [];
    connection.bufferedBytes = 0;
    this.#connections.delete(id);
  }

  #closePeerObjects(connection: RelayConnectionRuntime) {
    this.#stopIceRttPolling(connection);
    try {
      connection.dataChannel?.close?.();
    } catch {}
    try {
      connection.peerConnection?.close?.();
    } catch {}
    connection.dataChannel = null;
    connection.peerConnection = null;
  }

  async #loadWrtc() {
    if (!this.#wrtcPromise) {
      this.#wrtcPromise = Promise.resolve().then(() => {
        const wrtcPath = require.resolve("@roamhq/wrtc", {
          paths: WRTC_RESOLVE_PATHS,
        });
        const module = require(wrtcPath);
        return (module.default || module) as any;
      });
    }
    return this.#wrtcPromise;
  }

  #log(
    level: "log" | "warn" | "error",
    message: string,
    details?: Record<string, unknown>,
  ) {
    this.config.onLog?.(level, message, details);
  }
}
