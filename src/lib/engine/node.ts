/**
 * WhatsAppVoipNode — the top-level call engine.
 *
 * Owns the call lifecycle and delegates relay setup, E2E keying, and
 * stanza processing to focused modules within this directory.
 */

import { randomBytes } from "node:crypto";

import {
  type CallInfo,
  type SignalingMessage,
  type StartCallOptions,
  type VoipCallbacks,
  type VoipConfig,
} from "../core/types";
import {
  deriveE2ESframeKey,
  deriveFingerprintHmacHex,
  deriveWasmParticipantSsrc,
  splitRawE2E,
} from "../core/crypto";
import { classifyPacket, parseDatagram } from "../protocol/protocol";
import {
  type StanzaEnvelope,
  type AcceptStanza,
  type RelayInfo,
  type TransportInfo,
  type ExtraXmlNode,
  decodeSignalingXml,
  parseStanza,
  renderXmlNode,
  extraXmlNode,
} from "../protocol/xmpp";
import { transportToRelayListUpdate } from "../relay/relayTransport";
import { SrtpContext, deriveHbhSrtpSecrets, type HbhSrtpSecrets } from "../crypto/srtp";
import { SframeContext } from "../crypto/sframe";
import { RelayMediaBridge } from "../relay/relayMedia";
import { RelayController } from "../relay/relayController";
import { MediaPipeline } from "../media/mediaPipeline";
import type { RelayStreamSubscriptionEntry } from "../protocol/relay";
import {
  traceCallEvent, traceCallInfoSnapshot, traceMarker, traceStanza,
} from "../app/trace";

import { type MutableCallInfo, orderOfferDestinations, buildDefaultRelayStreamPlan, decodePrimitiveEndpoint } from "./helpers";
import { buildDownlinkContext, deriveUplinkKeySet, relockDownlink } from "./e2e";
import { type RelaySetupCtx, applyTransport, disposeControllers } from "./relay-setup";

export class WhatsAppVoipNode {
  #config: VoipConfig;
  #callbacks?: VoipCallbacks;
  #initialized = false;
  #selfPnJid = "";
  #selfPnBareJid = "";
  #selfLidJid = "";
  #callInfo: MutableCallInfo | null = null;

  #senderSsrc = 0;
  #transportInfo: TransportInfo | null = null;
  #relaySecrets: HbhSrtpSecrets | null = null;
  #uplinkSrtp: SrtpContext | null = null;
  #downlinkSrtp: SrtpContext | null = null;
  #sframeKey: Uint8Array | null = null;
  #sframeContext: SframeContext | null = null;
  #mediaBridge: RelayMediaBridge | null = null;
  #relayControllers: RelayController[] = [];
  #mediaPipeline: MediaPipeline | null = null;
  #streamSubscriptions: RelayStreamSubscriptionEntry[] = [];
  #rtpStats = { sent: 0, received: 0, rtcpSent: 0, rtcpReceived: 0, octetsSent: 0, octetsReceived: 0 };
  #engineSendCallback: ((data: Uint8Array, ip: string, port: number) => unknown) | null = null;

  #e2eCallKey: Buffer | null = null;
  #e2eRawE2E: Buffer | null = null;
  #e2eSelfLid = "";
  #e2ePeerLid = "";
  #e2eExpectedPeerSsrcs: number[] = [];
  #e2ePeerDeviceLids: string[] = [];
  #e2eCallId = "";
  #e2ePeerLidLocked = false;

  constructor(config: VoipConfig = {}) {
    this.#config = { ...config, enableLogs: config.enableLogs !== false };
    this.#callbacks = config.callbacks;
    this.#senderSsrc = config.senderSsrc ? config.senderSsrc >>> 0 : (randomBytes(4).readUInt32BE(0) >>> 0) || 0xa00b00c0;
    this.#streamSubscriptions = config.streamSubscriptions ? [...config.streamSubscriptions] : [];
    traceMarker("voip_node_constructed", { useXmppOffer: this.#config.useXmppOffer === true, audioSource: this.#config.audioSource, senderSsrc: this.#senderSsrc });
  }

  #log = (level: string, m: string) => { if (this.#config.enableLogs !== false) this.#callbacks?.onLog?.(level as any, m); };
  #ensureInit() { if (!this.#initialized) throw new Error("WhatsAppVoipNode not initialized"); }

  #relayCtx(): RelaySetupCtx {
    return {
      e2eCallKey: this.#e2eCallKey, e2eRawE2E: this.#e2eRawE2E, e2eSelfLid: this.#e2eSelfLid,
      e2ePeerLid: this.#e2ePeerLid, e2eExpectedPeerSsrcs: this.#e2eExpectedPeerSsrcs,
      e2ePeerDeviceLids: this.#e2ePeerDeviceLids, e2eCallId: this.#e2eCallId, e2ePeerLidLocked: this.#e2ePeerLidLocked,
      senderSsrc: this.#senderSsrc, transportInfo: this.#transportInfo,
      uplinkSrtp: this.#uplinkSrtp, downlinkSrtp: this.#downlinkSrtp, relaySecrets: this.#relaySecrets,
      mediaBridge: this.#mediaBridge, mediaPipeline: this.#mediaPipeline, relayControllers: this.#relayControllers,
      streamSubscriptions: this.#streamSubscriptions, config: this.#config, rtpStats: this.#rtpStats,
      engineSendCallback: this.#engineSendCallback,
      callbacks: { onAudioPlaybackData: this.#callbacks?.onAudioPlaybackData },
      onMediaPipelineReady: (p) => { this.#mediaPipeline = p; },
      log: this.#log,
    };
  }

  #adoptRelayCtx(ctx: RelaySetupCtx) {
    this.#transportInfo = ctx.transportInfo;
    this.#uplinkSrtp = ctx.uplinkSrtp; this.#downlinkSrtp = ctx.downlinkSrtp; this.#relaySecrets = ctx.relaySecrets;
    this.#mediaBridge = ctx.mediaBridge; this.#mediaPipeline = ctx.mediaPipeline; this.#relayControllers = ctx.relayControllers;
    this.#streamSubscriptions = ctx.streamSubscriptions;
    this.#rtpStats = ctx.rtpStats;
    this.#engineSendCallback = ctx.engineSendCallback;
    this.#e2eCallKey = ctx.e2eCallKey; this.#e2eRawE2E = ctx.e2eRawE2E; this.#e2eSelfLid = ctx.e2eSelfLid;
    this.#e2ePeerLid = ctx.e2ePeerLid; this.#e2eExpectedPeerSsrcs = ctx.e2eExpectedPeerSsrcs;
    this.#e2ePeerDeviceLids = ctx.e2ePeerDeviceLids; this.#e2eCallId = ctx.e2eCallId; this.#e2ePeerLidLocked = ctx.e2ePeerLidLocked;
  }

  /* ---- Public API ---- */

  async initialize() {
    if (this.#initialized) throw new Error("WhatsAppVoipNode already initialized");
    this.#initialized = true;
    this.#log("log", "Initializing pure Node.js VoIP stack");
    traceMarker("voip_node_initialized", {});
    this.#callbacks?.onVoipReady?.();
  }

  initVoipStack(selfPnJid?: string, selfPnBareJid?: string, selfLidJid?: string): number {
    this.#ensureInit();
    this.#selfPnJid = selfPnJid || ""; this.#selfPnBareJid = selfPnBareJid || ""; this.#selfLidJid = selfLidJid || "";
    return 0;
  }

  setRelaySendCallback(cb: (packet: Uint8Array, ip: string, port: number) => unknown) {
    this.#engineSendCallback = cb;
    for (const c of this.#relayControllers) { if (c.getState() === "creating") c.start(cb); }
  }

  setE2ECallKey(callKey: Uint8Array, selfLid: string, peerLid?: string, peerDeviceLids?: string[]) {
    this.#e2eCallKey = Buffer.from(callKey);
    this.#e2eSelfLid = selfLid;
    this.#e2ePeerLid = peerLid || "";
    const cands = [this.#e2ePeerLid, ...(peerDeviceLids ?? [])].filter((l) => l?.length);
    this.#e2ePeerDeviceLids = [...new Set(cands)];
    this.#e2ePeerLidLocked = false;
    traceMarker("voip_node_e2e_call_key_set", { callKeyHex: this.#e2eCallKey.toString("hex"), selfLid, peerLid: this.#e2ePeerLid, peerDeviceLids: this.#e2ePeerDeviceLids });
  }

  startCall(options: StartCallOptions): number {
    this.#ensureInit();
    this.#applyCallDerivedMediaPlan(options.callId);
    this.#callInfo = { callId: options.callId, peerJid: options.peerJid, isVideo: options.isVideo, isGroupCall: Boolean(options.isGroupCall), state: "calling", muted: false, videoMuted: false };
    this.#emitCallEvent(1, this.#callInfo);
    const payload = this.#config.useXmppOffer
      ? Buffer.from(this.#buildOfferXml(options), "utf8")
      : Buffer.from(JSON.stringify(this.#buildOfferSignal(options)), "utf8");
    if (this.#config.useXmppOffer) traceStanza("out", { tag: "offer", attrs: { "call-id": options.callId } });
    void this.#callbacks?.onSignalingXmpp?.(options.peerJid, options.callId, payload);
    return 0;
  }

  endCall(reason = 0, sendTerminate = true) {
    if (!this.#callInfo) return;
    this.#callInfo.state = "ended";
    this.#emitCallEvent(100, { ...this.#callInfo, reason, sendTerminate });
    this.#callInfo = null;
  }

  destroy() {
    this.endCall(0, false); this.#doResetMedia("destroy");
    this.#transportInfo = null; this.#relaySecrets = null; this.#uplinkSrtp = null; this.#downlinkSrtp = null;
    this.#sframeKey = null; this.#e2eCallKey = null; this.#e2eRawE2E = null; this.#e2eSelfLid = "";
    this.#sframeContext = null; this.#mediaBridge = null; this.#engineSendCallback = null;
    this.#initialized = false;
  }

  getCallInfo(): CallInfo | null { return this.#callInfo ? { ...this.#callInfo } : null; }
  getSenderSsrc(): number { return this.#senderSsrc >>> 0; }
  getExpectedPeerSsrcs(): number[] { return [...this.#e2eExpectedPeerSsrcs]; }

  getMediaStats() {
    if (this.#mediaPipeline) {
      const s = this.#mediaPipeline.getStats();
      Object.assign(this.#rtpStats, { sent: s.rtpSent, received: s.rtpReceived, rtcpSent: s.rtcpSent, rtcpReceived: s.rtcpReceived, octetsSent: s.octetsSent, octetsReceived: s.octetsReceived });
    }
    return {
      rtpSent: this.#rtpStats.sent, rtpReceived: this.#rtpStats.received, rtcpSent: this.#rtpStats.rtcpSent, rtcpReceived: this.#rtpStats.rtcpReceived, octetsSent: this.#rtpStats.octetsSent, octetsReceived: this.#rtpStats.octetsReceived,
      lastRtt: null as number | null,
      relayControllerStates: this.#relayControllers.map((c) => { const s = c.getStats(); return { id: c.id, state: s.state, allocateAttempts: s.allocateAttempts, bindAttempts: s.bindAttempts, pingAttempts: s.pingAttempts, keepaliveAttempts: s.keepaliveAttempts }; }),
    };
  }

  #doResetMedia(reason = "reset") {
    if (this.#mediaPipeline) { try { this.#mediaPipeline.stop(); } catch {} this.#mediaPipeline = null; }
    const ctx = this.#relayCtx();
    disposeControllers(ctx);
    this.#adoptRelayCtx(ctx);
    traceMarker("media_reset", { reason });
  }

  resetMedia(reason = "reset") {
    this.#doResetMedia(reason);
  }

  /* ---- Signaling ---- */

  handleSignalingAck(msg: SignalingMessage) {
    try {
      const parsed = parseStanza(decodeSignalingXml(msg.payload));
      if (parsed.kind === "ack") {
        const ctx = this.#relayCtx();
        applyTransport(ctx, parsed.ack.callId, parsed.ack.relay);
        this.#adoptRelayCtx(ctx);
        this.#emitRelayUpdate(parsed.ack.callId, parsed.ack.relay);
      } else if (parsed.kind === "relay") {
        const callId = parsed.callId || this.#callInfo?.callId || "";
        const ctx = this.#relayCtx();
        applyTransport(ctx, callId, parsed.relay);
        this.#adoptRelayCtx(ctx);
        this.#emitRelayUpdate(callId, parsed.relay);
      }
    } catch {}
    if (this.#callInfo) { this.#callInfo.state = "ack"; this.#emitCallEvent(1, this.#callInfo); }
  }

  handleSignalingMessage(msg: { payload: string | Uint8Array }) {
    this.#ingestStanza(parseStanza(decodeSignalingXml(msg.payload)));
  }

  /* ---- Media ---- */

  feedRelayDatagram(packet: Uint8Array, host = "", port = 0) {
    this.#ensureInit();
    const kind = classifyPacket(packet);
    if (kind === "stun") {
      const t = this.#relayControllers.find((c) => c.ip === host && c.port === port);
      if (t) t.handleIncomingStun(packet);
      else if (this.#relayControllers.length > 0) this.#relayControllers[0]!.handleIncomingStun(packet);
      return parseDatagram(packet, host, port);
    }
    if (kind === "rtp" && (this.#e2eCallKey || this.#e2eRawE2E) && !this.#e2ePeerLidLocked && packet.length >= 12) {
      const ssrc = ((packet[8]! << 24) | (packet[9]! << 16) | (packet[10]! << 8) | packet[11]!) >>> 0;
      const result = relockDownlink(
        this.#e2eRawE2E, this.#e2eCallKey, this.#transportInfo, this.#e2eCallId, this.#e2eSelfLid,
        this.#e2eExpectedPeerSsrcs, this.#e2ePeerDeviceLids, this.#senderSsrc,
        this.#uplinkSrtp, this.#mediaBridge, this.#mediaPipeline, ssrc, this.#log.bind(this),
      );
      if (result) {
        this.#e2ePeerLidLocked = true;
        this.#e2eExpectedPeerSsrcs = result.peerSsrcs;
        this.#downlinkSrtp = result.downlinkSrtp;
        this.#mediaBridge = result.mediaBridge;
      }
    }
    if ((kind === "rtp" || kind === "rtcp") && this.#mediaPipeline) {
      const info = this.#mediaPipeline.feedDatagram(packet, host, port);
      const s = this.#mediaPipeline.getStats();
      Object.assign(this.#rtpStats, { received: s.rtpReceived, rtcpReceived: s.rtcpReceived, octetsReceived: s.octetsReceived, octetsSent: s.octetsSent, rtcpSent: s.rtcpSent });
      return info;
    }
    if (this.#mediaBridge && (kind === "rtp" || kind === "rtcp")) {
      return this.#mediaBridge.handleIncomingDatagram(packet, host, port);
    }
    return parseDatagram(packet, host, port);
  }

  /* ---- Static helpers ---- */

  static parseStanza(xml: string): StanzaEnvelope { return parseStanza(xml); }

  static deriveAcceptMaterial(rawE2E: string, fingerprintHex?: string) {
    const s = splitRawE2E(rawE2E);
    return { split: s, e2eSframeKey: deriveE2ESframeKey(rawE2E), fingerprintHmac: fingerprintHex ? deriveFingerprintHmacHex(rawE2E, fingerprintHex) : undefined };
  }

  static deriveRelayMaterial(transport: Pick<TransportInfo, "hbhKey" | "key">) {
    const secrets = deriveHbhSrtpSecrets(transport.hbhKey, transport.key);
    return { hbhSrtpKey: secrets.srtp.encryptionKey, hbhSrtpAuthKey: secrets.srtp.authenticationKey, hbhSrtpSalt: secrets.srtp.salt, uplinkHbhSrtcpKey: secrets.uplinkSrtcp.encryptionKey, uplinkHbhSrtcpAuthKey: secrets.uplinkSrtcp.authenticationKey, uplinkHbhSrtcpSalt: secrets.uplinkSrtcp.salt, downlinkHbhSrtcpKey: secrets.downlinkSrtcp.encryptionKey, downlinkHbhSrtcpAuthKey: secrets.downlinkSrtcp.authenticationKey, downlinkHbhSrtcpSalt: secrets.downlinkSrtcp.salt };
  }

  /* ---- Private: event emission + helpers ---- */

  #emitCallEvent(eventType: number, eventData: unknown) {
    try { traceCallEvent(eventType, eventData); if (this.#callInfo) traceCallInfoSnapshot(this.#callInfo); } catch {}
    this.#callbacks?.onCallEvent?.(eventType, JSON.stringify(eventData));
  }

  #emitRelayUpdate(callId: string, relayInfo?: RelayInfo) {
    const t = relayInfo?.transport; if (!t) return;
    const ru = transportToRelayListUpdate(t); if (ru.relays.length === 0) return;
    this.#emitCallEvent(156, { ...ru, call_id: callId || this.#callInfo?.callId || "", peer_pid: relayInfo?.peerPid, self_pid: relayInfo?.selfPid, relay_uuid: relayInfo?.uuid || "", relay_participants: (relayInfo?.participants || []).map((p) => ({ pid: p.pid, jid: p.jid })), hbh_key: t.hbhKey || "", xtoken_id: t.xtokenId, auth_token_id: t.authTokenId, warp_mi_tag_len: t.warpMiTagLen, prefer_relay: t.preferRelay, peer_dl: t.peerDl, prefer_ipv6: t.preferIpv6, smart_transport_signal: t.smartTransportSignal || "", transport_relay_name: t.relayName || "", transport_domain_name: t.domainName || "", endpoint_family: t.te.length > 0 ? "te" : t.te2.length > 0 ? "te2" : "none", te_count: t.te.length, te2_count: t.te2.length });
  }

  #applyCallDerivedMediaPlan(callId: string) {
    if (!this.#selfLidJid) return;
    if (!this.#config.senderSsrc) this.#senderSsrc = deriveWasmParticipantSsrc(callId, this.#selfLidJid, 0);
    if (!this.#config.streamSubscriptions || this.#config.streamSubscriptions.length === 0)
      this.#streamSubscriptions = buildDefaultRelayStreamPlan(this.#senderSsrc, callId, this.#selfLidJid);
  }

  #buildOfferSignal(options: StartCallOptions) {
    const ordered = orderOfferDestinations(options.peerList?.length ? options.peerList : [options.peerJid]);
    return { internal: "node-offer-v1", callId: options.callId, peerJid: options.peerJid, peerPn: options.peerPn, callCreator: this.#selfLidJid || this.#selfPnJid || this.#selfPnBareJid || "", isVideo: options.isVideo, privacyHex: "040128dc013eafc5f52609", capabilityHex: "0105f709e4bb13", destinations: ordered.map((jid) => ({ jid, count: 0, callKeyB64: randomBytes(32).toString("base64") })) };
  }

  #buildOfferXml(options: StartCallOptions): string {
    const ordered = orderOfferDestinations(options.peerList?.length ? options.peerList : [options.peerJid]);
    const key = randomBytes(32);
    const creator = this.#selfLidJid || this.#selfPnJid || this.#selfPnBareJid || "";
    return renderXmlNode("offer", { "call-id": options.callId, "call-creator": creator }, [
      extraXmlNode("privacy", {}, ["040128dc013eafc5f52609"]),
      extraXmlNode("audio", { enc: "opus", rate: "8000" }), extraXmlNode("audio", { enc: "opus", rate: "16000" }),
      extraXmlNode("net", { medium: "3" }), extraXmlNode("capability", { ver: "1" }, ["0105f709e4bb13"]),
      extraXmlNode("destination", {}, ordered.map((jid) => extraXmlNode("to", { jid }, [extraXmlNode("enc", { v: "2", count: "0" }, [key.toString("base64")])]))),
      extraXmlNode("encopt", { keygen: "2" }),
    ]);
  }

  /* ---- Stanza dispatcher ---- */

  #ingestStanza(stanza: StanzaEnvelope) {
    this.#ensureInit();
    traceStanza("in", stanza);
    switch (stanza.kind) {
      case "offer": {
        this.#callInfo = { ...(this.#callInfo ?? {}), callId: stanza.offer.callId, peerJid: stanza.offer.callCreator, state: stanza.offer.state || "offer" };
        const ctx = this.#relayCtx();
        applyTransport(ctx, stanza.offer.callId, stanza.offer.relay);
        this.#adoptRelayCtx(ctx);
        this.#emitRelayUpdate(stanza.offer.callId, stanza.offer.relay);
        this.#emitCallEvent(1, this.#callInfo);
        break;
      }
      case "preaccept": {
        this.#callInfo = { ...(this.#callInfo ?? {}), callId: stanza.preaccept.callId, peerJid: stanza.preaccept.deviceJid || stanza.preaccept.callCreator || this.#callInfo?.peerJid || "", state: "preaccept" };
        this.#emitCallEvent(1, this.#callInfo);
        break;
      }
      case "accept": this.#handleAccept(stanza.accept); break;
      case "terminate": this.#handleTerminate(stanza.terminate.callId, stanza.terminate.callCreator, stanza.terminate.reason); break;
      case "reject": this.#handleTerminate(stanza.reject.callId, stanza.reject.callCreator, stanza.reject.reason || "rejected"); break;
    }
  }

  #handleTerminate(callId: string, peerJid: string, reason: string) {
    const r = String(reason || "").trim().toLowerCase();
    this.#emitCallEvent(100, { ...(this.#callInfo ?? {}), callId: callId || this.#callInfo?.callId || "", peerJid: peerJid || this.#callInfo?.peerJid || "", state: r === "accepted_elsewhere" ? "accepted_elsewhere" : r === "rejected_elsewhere" ? "rejected_elsewhere" : r || "ended", reason: r, sendTerminate: false });
    this.#callInfo = null;
  }

  #handleAccept(accept: AcceptStanza) {
    traceMarker("handle_accept", { callId: accept.callId, hasRelay: !!accept.relay });
    const peerJid = accept.deviceJid || accept.relay?.participants.find((p) => p.jid)?.jid || accept.callCreator || this.#callInfo?.peerJid || "";
    this.#callInfo = { ...(this.#callInfo ?? {}), callId: accept.callId, peerJid, state: "accepted" };
    if (accept.rawE2E) { try { this.#e2eRawE2E = Buffer.from(splitRawE2E(accept.rawE2E).baseMaterial); } catch { this.#e2eRawE2E = null; } }
    const ctx = this.#relayCtx();
    applyTransport(ctx, accept.callId, accept.relay);
    this.#adoptRelayCtx(ctx);
    this.#emitRelayUpdate(accept.callId, accept.relay);
    this.#retargetToConvergedRelay(accept.relay);
    if (accept.rawE2E) { this.#sframeKey = deriveE2ESframeKey(accept.rawE2E); this.#sframeContext = new SframeContext(this.#sframeKey); }
    this.#emitCallEvent(1, this.#callInfo);
  }

  #retargetToConvergedRelay(relayInfo?: RelayInfo) {
    const t = relayInfo?.transport; if (!t || !this.#mediaPipeline) return;
    for (const ep of (t.te.length > 0 ? t.te : t.te2)) {
      const d = decodePrimitiveEndpoint(ep.host, ep.rawContent); if (!d) continue;
      if (this.#config.disableIpv6 !== false && d.ip.includes(":")) continue;
      this.#mediaPipeline.setTargets([{ ip: d.ip, port: d.port }]);
      this.#log("log", `media uplink re-targeted to converged relay ${d.ip}:${d.port}`);
      traceMarker("media_retargeted_accept", { ip: d.ip, port: d.port });
      return;
    }
  }
}
