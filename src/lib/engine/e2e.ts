/**
 * Engine E2E keying: derivation, downlink relocking, and call key setup.
 *
 * Pure functions — no class state. All needed state is passed as parameters.
 */

import type { Buffer } from "node:buffer";

import { deriveE2EKeys, deriveE2EKeysFromRawE2E } from "../crypto/srtp1to1";
import { SrtpContext, type SrtpKeySet } from "../crypto/srtp";
import { RelayMediaBridge } from "../relay/relayMedia";
import type { TransportInfo } from "../protocol/xmpp";
import { deriveWasmParticipantSsrc } from "../core/crypto";
import { diagE2EKeys, diagSsrcPlan } from "../app/diag";
import { traceMarker } from "../app/trace";

export function deriveE2EForLid(e2eRawE2E: Buffer | null, e2eCallKey: Buffer | null, lid: string) {
  if (e2eRawE2E && e2eRawE2E.length >= 32) {
    return deriveE2EKeysFromRawE2E(e2eRawE2E, lid);
  }
  return deriveE2EKeys(e2eCallKey!, lid);
}

export function buildDownlinkContext(
  e2eRawE2E: Buffer | null,
  e2eCallKey: Buffer | null,
  transportInfo: TransportInfo | null,
  downlinkLid: string,
): SrtpContext {
  const keys = deriveE2EForLid(e2eRawE2E, e2eCallKey, downlinkLid);
  const keySet: SrtpKeySet = {
    encryptionKey: keys.cipherKey, authenticationKey: keys.authKey, salt: keys.salt,
  };
  const warpTagLen = (transportInfo && transportInfo.warpMiTagLen > 0) ? transportInfo.warpMiTagLen : 4;
  diagE2EKeys("downlink", { lid: downlinkLid, cipherKey: keys.cipherKey, authKey: keys.authKey, salt: keys.salt, warpMiTagLen: warpTagLen });
  return new SrtpContext({ srtp: keySet, srtcp: keySet, authTagLength: warpTagLen, verifyRtpAuth: false });
}

export function deriveUplinkKeySet(e2eRawE2E: Buffer | null, e2eCallKey: Buffer | null, selfLid: string): { keys: ReturnType<typeof deriveE2EKeys>; keySet: SrtpKeySet } {
  const keys = deriveE2EForLid(e2eRawE2E, e2eCallKey, selfLid);
  return { keys, keySet: { encryptionKey: keys.cipherKey, authenticationKey: keys.authKey, salt: keys.salt } };
}

export interface RelockResult {
  matchedLid: string;
  peerSsrcs: number[];
  downlinkSrtp: SrtpContext;
  mediaBridge: RelayMediaBridge | null;
}

export function relockDownlink(
  e2eRawE2E: Buffer | null,
  e2eCallKey: Buffer | null,
  transportInfo: TransportInfo | null,
  e2eCallId: string,
  e2eSelfLid: string,
  e2eExpectedPeerSsrcs: number[],
  e2ePeerDeviceLids: string[],
  senderSsrc: number,
  uplinkSrtp: SrtpContext | null,
  mediaBridge: RelayMediaBridge | null,
  mediaPipeline: { setDownlink: (s: SrtpContext, p?: number[]) => void } | null,
  ssrc: number,
  log: (level: string, msg: string) => void,
): RelockResult | null {
  const slots = [0, 1, 2, 3];
  let matchedLid: string | null = null;
  for (const lid of e2ePeerDeviceLids) {
    if (slots.map((s) => deriveWasmParticipantSsrc(e2eCallId, lid, s)).includes(ssrc >>> 0)) {
      matchedLid = lid; break;
    }
  }
  if (!matchedLid) return null;

  const peerSsrcs = slots.map((s) => deriveWasmParticipantSsrc(e2eCallId, matchedLid!, s));
  const downlink = buildDownlinkContext(e2eRawE2E, e2eCallKey, transportInfo, matchedLid);
  let bridge = mediaBridge;
  if (mediaBridge && uplinkSrtp) {
    bridge = new RelayMediaBridge({ uplink: uplinkSrtp, downlink });
  }
  mediaPipeline?.setDownlink(downlink, peerSsrcs);

  diagSsrcPlan({
    callId: e2eCallId, selfLid: e2eSelfLid, peerLid: matchedLid, senderSsrc,
    expectedSelfSsrcs: slots.map((s) => deriveWasmParticipantSsrc(e2eCallId, e2eSelfLid, s)),
    expectedPeerSsrcs: peerSsrcs,
  });
  traceMarker("voip_node_e2e_downlink_relocked", {
    ssrcHex: (ssrc >>> 0).toString(16), peerDeviceLid: matchedLid, expectedPeerSsrcs: peerSsrcs,
  });
  log("log", `e2e-srtp downlink relocked to answering device LID ${matchedLid} (ssrc=0x${(ssrc >>> 0).toString(16)})`);
  return { matchedLid, peerSsrcs, downlinkSrtp: downlink, mediaBridge: bridge };
}
