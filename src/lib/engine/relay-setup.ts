/**
 * Relay transport setup: apply transport info, spawn relay controllers,
 * and start the media pipeline.
 *
 * Pure functions that take all needed state as parameters.
 */

import { randomBytes } from "node:crypto";
import type { TransportInfo, RelayInfo } from "../protocol/xmpp";
import type { RelayStreamSubscriptionEntry } from "../protocol/relay";
import { transportToRelayListUpdate } from "../relay/relayTransport";
import { RelayController } from "../relay/relayController";
import { RelayMediaBridge } from "../relay/relayMedia";
import { MediaPipeline } from "../media/mediaPipeline";
import { SrtpContext, deriveHbhSrtpSecrets, type SrtpKeySet } from "../crypto/srtp";
import type { HbhSrtpSecrets } from "../crypto/srtp";
import { diagE2EKeys, diagSsrcPlan } from "../app/diag";
import { traceMarker } from "../app/trace";
import { deriveE2EForLid, deriveUplinkKeySet } from "./e2e";
import { deriveWasmParticipantSsrc } from "../core/crypto";
import {
  envNumber, envBool, envAudioFilter,
  collectStreamSubscriptionsFromOffer, buildDefaultRelayStreamPlan,
  decodePrimitiveEndpoint, decodeConnIdHint, deriveRelayConnId,
} from "./helpers";

export interface RelaySetupCtx {
  e2eCallKey: Buffer | null;
  e2eRawE2E: Buffer | null;
  e2eSelfLid: string;
  e2ePeerLid: string;
  e2eExpectedPeerSsrcs: number[];
  e2ePeerDeviceLids: string[];
  e2eCallId: string;
  e2ePeerLidLocked: boolean;
  senderSsrc: number;
  transportInfo: TransportInfo | null;
  uplinkSrtp: SrtpContext | null;
  downlinkSrtp: SrtpContext | null;
  relaySecrets: HbhSrtpSecrets | null;
  mediaBridge: RelayMediaBridge | null;
  mediaPipeline: MediaPipeline | null;
  relayControllers: RelayController[];
  streamSubscriptions: RelayStreamSubscriptionEntry[];
  config: { audioSource?: string; disableIpv6?: boolean; relayControl?: { keepaliveIntervalMs?: number; pingIntervalMs?: number; allocateRetryMs?: number } };
  rtpStats: { sent: number; received: number; rtcpSent: number; rtcpReceived: number; octetsSent: number; octetsReceived: number };
  engineSendCallback: ((data: Uint8Array, ip: string, port: number) => unknown) | null;
  callbacks: {
    onAudioPlaybackData?: (samples: Float32Array) => void;
  };
  log: (level: string, msg: string) => void;
  /** Called by startPipeline when the async pipeline is ready. */
  onMediaPipelineReady?: (p: MediaPipeline) => void;
}

export function applyTransport(ctx: RelaySetupCtx, callId: string, relayInfo?: RelayInfo): void {
  const t = relayInfo?.transport;
  if (!t) {
    traceMarker("apply_relay_transport", { callId, hasTransport: false });
    return;
  }
  try {
    const eps = (t.te.length > 0 ? t.te : t.te2).map((e) => e.relayName || e.host).join(",");
    traceMarker("apply_relay_transport", { callId, endpoints: eps, mediaRunning: !!ctx.mediaPipeline });
  } catch {}
  ctx.transportInfo = t;

  if ((ctx.e2eCallKey || ctx.e2eRawE2E) && ctx.e2eSelfLid) {
    ctx.e2eCallId = callId;
    ctx.e2ePeerLidLocked = false;
    const uplink = deriveE2EForLid(ctx.e2eRawE2E, ctx.e2eCallKey, ctx.e2eSelfLid);
    const downlinkLid = ctx.e2ePeerDeviceLids[0] || ctx.e2ePeerLid || ctx.e2eSelfLid;
    const downlink = deriveE2EForLid(ctx.e2eRawE2E, ctx.e2eCallKey, downlinkLid);
    const warpTagLen = t.warpMiTagLen > 0 ? t.warpMiTagLen : 4;

    ctx.uplinkSrtp = new SrtpContext({
      srtp: { encryptionKey: uplink.cipherKey, authenticationKey: uplink.authKey, salt: uplink.salt },
      srtcp: { encryptionKey: uplink.cipherKey, authenticationKey: uplink.authKey, salt: uplink.salt },
      authTagLength: warpTagLen, verifyRtpAuth: false,
    });
    ctx.downlinkSrtp = new SrtpContext({
      srtp: { encryptionKey: downlink.cipherKey, authenticationKey: downlink.authKey, salt: downlink.salt },
      srtcp: { encryptionKey: downlink.cipherKey, authenticationKey: downlink.authKey, salt: downlink.salt },
      authTagLength: warpTagLen, verifyRtpAuth: false,
    });
    ctx.mediaBridge = new RelayMediaBridge({ uplink: ctx.uplinkSrtp, downlink: ctx.downlinkSrtp });
    ctx.relaySecrets = null;

    diagE2EKeys("uplink", { lid: ctx.e2eSelfLid, cipherKey: uplink.cipherKey, authKey: uplink.authKey, salt: uplink.salt, warpMiTagLen: warpTagLen });
    diagE2EKeys("downlink", { lid: downlinkLid, cipherKey: downlink.cipherKey, authKey: downlink.authKey, salt: downlink.salt, warpMiTagLen: warpTagLen });

    const slots = [0, 1, 2, 3];
    const selfSsrcs = slots.map((s) => deriveWasmParticipantSsrc(callId, ctx.e2eSelfLid, s));
    ctx.e2eExpectedPeerSsrcs = slots.map((s) => deriveWasmParticipantSsrc(callId, downlinkLid, s));
    diagSsrcPlan({ callId, selfLid: ctx.e2eSelfLid, peerLid: downlinkLid, senderSsrc: ctx.senderSsrc,
      expectedSelfSsrcs: selfSsrcs, expectedPeerSsrcs: ctx.e2eExpectedPeerSsrcs });

    spawnControllers(ctx, callId, relayInfo!);
    traceMarker("voip_node_e2e_srtp_active", {
      uplinkCipherKeyHex: Buffer.from(uplink.cipherKey).toString("hex"),
      uplinkAuthKeyHex: Buffer.from(uplink.authKey).toString("hex"),
      uplinkSaltHex: Buffer.from(uplink.salt).toString("hex"),
      downlinkCipherKeyHex: Buffer.from(downlink.cipherKey).toString("hex"),
      downlinkAuthKeyHex: Buffer.from(downlink.authKey).toString("hex"),
      downlinkSaltHex: Buffer.from(downlink.salt).toString("hex"),
      selfLid: ctx.e2eSelfLid, downlinkLid, warpMiTagLen: warpTagLen,
      expectedSelfSsrcs: selfSsrcs, expectedPeerSsrcs: ctx.e2eExpectedPeerSsrcs,
    });
  } else if (t.hbhKey && t.key) {
    ctx.relaySecrets = deriveHbhSrtpSecrets(t.hbhKey, t.key);
    const tagLen = t.warpMiTagLen > 0 ? t.warpMiTagLen : 4;
    ctx.uplinkSrtp = new SrtpContext({ srtp: ctx.relaySecrets.srtp, srtcp: ctx.relaySecrets.uplinkSrtcp, authTagLength: tagLen });
    ctx.downlinkSrtp = new SrtpContext({ srtp: ctx.relaySecrets.srtp, srtcp: ctx.relaySecrets.downlinkSrtcp, authTagLength: tagLen });
    ctx.mediaBridge = new RelayMediaBridge({ uplink: ctx.uplinkSrtp, downlink: ctx.downlinkSrtp });
    spawnControllers(ctx, callId, relayInfo!);
  }
}

export function spawnControllers(ctx: RelaySetupCtx, callId: string, relay: RelayInfo): void {
  const t = relay.transport;
  if (!t) return;
  const ru = transportToRelayListUpdate(t);
  const tokens = ru.relay_tokens ?? [];
  if (tokens.length === 0) return;
  const keyBytes = Buffer.from(ru.relay_key, "utf8");
  const subs = ctx.streamSubscriptions.length > 0 ? ctx.streamSubscriptions : collectStreamSubscriptionsFromOffer(relay);
  const eps = t.te.length > 0 ? t.te : t.te2;
  if (eps.length === 0) return;

  disposeControllers(ctx);
  let primaryReady = false;

  const disableIpv6 = ctx.config.disableIpv6 !== false;
  const rc = ctx.config.relayControl;

  for (let i = 0; i < eps.length; i++) {
    const ep = eps[i]!;
    const d = decodePrimitiveEndpoint(ep.host, ep.rawContent);
    if (!d) continue;
    if (disableIpv6 && d.ip.includes(":")) continue;
    const tidx = Number.parseInt(ep.tokenId, 10);
    const tokB64 = Number.isFinite(tidx) ? tokens[tidx] ?? tokens[0] : tokens[0];
    if (!tokB64) continue;

    const ctrl = new RelayController({
      id: `${d.ip}:${d.port}`, ip: d.ip, port: d.port,
      relayId: Number.parseInt(ep.relayId, 10) || 0,
      relayName: ep.relayName || t.relayName,
      relayToken: Buffer.from(tokB64, "base64"), relayKeyBytes: keyBytes,
      connIdData: (ru.conn_id ? decodeConnIdHint(ru.conn_id) : undefined)
        ?? decodeConnIdHint(t.connId) ?? deriveRelayConnId(d.ip, d.port),
      streamSubscriptions: subs.length > 0 ? subs : buildDefaultRelayStreamPlan(ctx.senderSsrc, callId, ctx.e2eSelfLid),
      keepaliveIntervalMs: rc?.keepaliveIntervalMs, pingIntervalMs: rc?.pingIntervalMs, allocateRetryMs: rc?.allocateRetryMs,
    });

    ctrl.on("state", (ev) => {
      ctx.log("log", `relay-controller ${ctrl.id} ${ev.previous}->${ev.current}`);
      traceMarker("relay_controller_event", { callId, id: ctrl.id, previous: ev.previous, current: ev.current });
    });

    const isPrimary = i === 0;
    ctrl.on("ready", () => {
      ctx.log("log", `relay-controller ${ctrl.id} READY`);
      traceMarker("relay_controller_ready", { callId, id: ctrl.id });
      if (ctx.mediaPipeline && isPrimary) {
        ctx.mediaPipeline.setTargets([{ ip: ctrl.ip, port: ctrl.port }]);
        ctx.log("log", `media uplink re-targeted to converged relay ${ctrl.id}`);
        traceMarker("media_retargeted", { callId, id: ctrl.id });
      }
      if (!primaryReady && isPrimary) {
        primaryReady = true;
        void startPipeline(ctx, ctrl).catch((e) => ctx.log("warn", `media pipeline start failed: ${String(e)}`));
      } else if (!primaryReady && !ctx.mediaPipeline) {
        primaryReady = true;
        void startPipeline(ctx, ctrl).catch((e) => ctx.log("warn", `media pipeline start failed: ${String(e)}`));
      }
    });

    ctrl.on("allocate_error", ({ id, code, reason }) => {
      ctx.log("warn", `relay-controller ${id} allocate rejected (code=${code}): ${reason}`);
      traceMarker("relay_allocate_error", { callId, id, code, reason });
      if (ctx.mediaPipeline) {
        const healthy = ctx.relayControllers.find((c) => c.id !== id && (c.getState() === "ready" || c.getState() === "bound"));
        if (healthy) {
          ctx.mediaPipeline.setTargets([{ ip: healthy.ip, port: healthy.port }]);
          ctx.log("log", `media uplink failed over to relay ${healthy.id}`);
          traceMarker("media_failover", { callId, id: healthy.id });
        }
      }
    });

    ctrl.on("log", ({ level, message, details }) => {
      ctx.log(level, `[relay-controller] ${ctrl.id} ${message} ${JSON.stringify(details ?? {})}`);
    });

    ctx.relayControllers.push(ctrl);
    if (ctx.engineSendCallback) ctrl.start(ctx.engineSendCallback);
  }
}

async function startPipeline(ctx: RelaySetupCtx, ctrl: RelayController): Promise<void> {
  if (ctx.mediaPipeline) return;
  if (!ctx.uplinkSrtp || !ctx.downlinkSrtp) return;
  if (!ctx.engineSendCallback) return;
  const src = ctx.config.audioSource;
  if (!src) { traceMarker("media_pipeline_skipped_no_source", { controllerId: ctrl.id }); return; }

  ctx.mediaPipeline = new MediaPipeline({
    source: src,
    uplink: ctx.uplinkSrtp, downlink: ctx.downlinkSrtp,
    senderSsrc: ctx.senderSsrc, expectedPeerSsrcs: ctx.e2eExpectedPeerSsrcs,
    sampleRate: 48000, channels: envNumber("CALL_AUDIO_CHANNELS", 1),
    bitrateBps: envNumber("CALL_MLOW_BITRATE_BPS", 25000),
    audioFilter: envAudioFilter("aresample=resampler=swr:cutoff=0.99"),
    audioPiggyback: envBool("CALL_AUDIO_PIGGYBACK", false),
    sendEveryNFrames: envNumber("CALL_AUDIO_SEND_EVERY_N", 1),
    initialSequenceNumber: 1,
    initialTimestamp: (randomBytes(2).readUInt16BE(0) >>> 0) & 0x7fff,
    targets: [{ ip: ctrl.ip, port: ctrl.port }],
    send: (pkt, ip, port) => { ctx.rtpStats.sent += 1; ctx.engineSendCallback?.(pkt, ip, port); },
    onAudioPlaybackData: (samples) => ctx.callbacks.onAudioPlaybackData?.(samples),
  });
  await ctx.mediaPipeline.start();
  ctx.onMediaPipelineReady?.(ctx.mediaPipeline);
  traceMarker("media_pipeline_started", { controllerId: ctrl.id, audioSource: src, senderSsrc: ctx.senderSsrc });
}

export function disposeControllers(ctx: RelaySetupCtx): void {
  for (const c of ctx.relayControllers) { try { c.close("rebuild"); } catch {} }
  ctx.relayControllers = [];
}
