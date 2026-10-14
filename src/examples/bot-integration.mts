/**
 * ============================================================================
 * Add WhatsApp calling to YOUR existing Baileys bot — minimal drop-in glue
 * ============================================================================
 *
 * `baileys-real-call.mts` is a standalone caller (it creates its own socket).
 * This file is the opposite: it assumes you ALREADY have a connected Baileys
 * socket (your bot) and only shows the glue to add calling to it.
 *
 *   import { attachCalling } from "./bot-integration.mts"
 *   const calling = attachCalling(sock)                                  // once
 *   await calling.placeCall("15551234567")                             // per call
 *
 * What you get: real 1:1 audio calls — MLow media over WhatsApp's relay,
 * Signal-encrypted call keys, SRTP, peer audio delivered as PCM.
 *
 * The three pieces of glue:
 *   1. Engine + relay transport bridge      (once, at startup)
 *   2. Outbound call: offer stanza          (per call — e.g. a bot command)
 *   3. Inbound `<call>` stanzas → engine    (once — a ws event hook)
 *
 * Run with tsx (examples are excluded from the tsc build):
 *   npx tsx src/examples/bot-integration.mts
 */

import { randomBytes } from "node:crypto";
import dgram from "node:dgram";

import {
  getAllBinaryNodeChildren,
  type BinaryNode,
  type WASocket,
} from "@whiskeysockets/baileys";

import { WhatsAppVoipNode } from "../index";
import {
  RelayRtcTransport,
} from "../lib/relay/RelayRtcTransport.mts";
import {
  toBareJid,
  binaryNodeToString,
  ensureSessions,
  encryptCallKeyForJid,
  buildOfferStanza,
  appendDeviceIdentity,
  sendCallStanza,
} from "../lib/app/whatsapp-signaling";

const S_WHATSAPP_NET = "@s.whatsapp.net";

export interface CallingHandle {
  /** Place a 1:1 audio call to a phone number (digits only). */
  placeCall(phoneNumber: string): Promise<string>;
  /** Hang up an active call. */
  endCall(callId: string): Promise<void>;
  /** The engine, if you need lower-level access (stats, SSRCs, …). */
  voip: WhatsAppVoipNode;
}

/**
 * Attach calling to an existing, connected Baileys socket.
 *
 * @param sock  your bot's makeWASocket() socket
 * @param audioSource  ffmpeg-decodable file or `lavfi:` spec streamed to the callee
 */
export async function attachCalling(
  sock: WASocket,
  audioSource = "lavfi:sine=frequency=440",
): Promise<CallingHandle> {
  const selfPnJid = String(sock.authState.creds.me?.id ?? "");
  const selfLidJid = String(sock.authState.creds.me?.lid ?? "");
  if (!selfLidJid) throw new Error("no LID on auth creds — reconnect the bot");

  // -----------------------------------------------------------------------
  // 1. Engine + relay transport bridge (once)
  // -----------------------------------------------------------------------
  const voip = new WhatsAppVoipNode({
    audioSource,
    callbacks: {
      onLog: (level, msg) => console.log(`[voip:${level}] ${msg}`),
      onCallEvent: (type, data) => {
        // type 156 = relay-list update → hand to the WebRTC transport
        if (type === 156 && relay) relay.updateRelayList(JSON.parse(data));
      },
      onAudioPlaybackData: (samples) => {
        // Float32Array @ 16 kHz mono from the peer — play or pipe to your TTS/ASR
      },
    },
  });
  await voip.initialize();
  voip.initVoipStack(selfPnJid, undefined, selfLidJid);

  // Production transport: WebRTC DataChannel to WhatsApp's relays (needs @roamhq/wrtc).
  // The UDP fallback below works for testing but is not relay-production-grade.
  const relay = new RelayRtcTransport({
    onTransportMessage: (data, ip, port) =>
      voip.feedRelayDatagram(new Uint8Array(data), ip, port),
  });
  voip.setRelaySendCallback((packet, ip, port) => relay.send(Buffer.from(packet), ip, port));

  // Testing fallback: raw UDP instead of the DataChannel transport.
  // const udp = dgram.createSocket("udp4");
  // voip.setRelaySendCallback((packet, ip, port) => udp.send(packet, port, ip));
  // udp.on("message", (msg, rinfo) => voip.feedRelayDatagram(new Uint8Array(msg), rinfo.address, rinfo.port));

  // -----------------------------------------------------------------------
  // 2. Outbound call (call this from your command handler)
  // -----------------------------------------------------------------------
  const ensuredSessions = new Set<string>();

  const placeCall = async (phoneNumber: string): Promise<string> => {
    const target = phoneNumber.replace(/\D/g, "");
    if (!target) throw new Error("phone number required");

    const peerPn = `${target}${S_WHATSAPP_NET}`;
    const peerLid = String(
      (await sock.signalRepository?.lidMapping?.getLIDForPN?.(peerPn)) ?? "",
    );
    if (!peerLid) throw new Error(`could not resolve LID for ${peerPn}`);

    // Signal sessions must exist before the call key can be encrypted per device
    await ensureSessions(sock, [peerLid], ensuredSessions, S_WHATSAPP_NET);
    const devices = (await sock.getUSyncDevices([peerLid], true, false))
      .map((d: any) => String(d.jid))
      .filter(Boolean);
    await ensureSessions(sock, devices, ensuredSessions, S_WHATSAPP_NET);

    const callId = randomBytes(16).toString("hex");
    const callKey = randomBytes(32); // one 32-byte key per call, encrypted per device

    // E2E keying — BEFORE the offer ack arrives
    voip.setE2ECallKey(callKey, selfLidJid, peerLid, devices);
    voip.startCall({ callId, peerJid: peerLid, peerPn, isVideo: false });

    // Build the <offer> (privacy → audio×2 → net → capability → destination → encopt)
    // with the 32-byte call key Signal-encrypted into each <enc> node.
    const { offer, routeTo, includeDeviceIdentity } = await buildOfferStanza(
      (jid, key, count) => encryptCallKeyForJid(sock, jid, key, count),
      callId,
      selfLidJid,
      peerLid,
      devices,
      callKey,
    );
    if (includeDeviceIdentity) await appendDeviceIdentity(sock, offer);
    await sendCallStanza(sock, voip, routeTo, offer, "offer");
    return callId;
  };

  const endCall = async (callId: string): Promise<void> => {
    await sendCallStanza(
      sock,
      voip,
      selfLidJid,
      {
        tag: "terminate",
        attrs: { "call-id": callId, "call-creator": selfLidJid, reason: "accepted" },
        content: [],
      },
      "terminate",
    );
  };

  // -----------------------------------------------------------------------
  // 3. Inbound `<call>` stanzas → engine (ack / preaccept / accept / terminate …)
  // -----------------------------------------------------------------------
  //
  // NOTE: this only covers signaling for calls THIS bot placed. To ANSWER an
  // incoming <offer>, extract the call key first, then set it on the engine and
  // reply with your own <accept> stanza (raw_e2e construction is yours):
  //
  //   import { parseInboundOfferLid, extractOfferEnc, decryptInboundCallKey } from "../lib/app/whatsapp-signaling";
  //   const enc = extractOfferEnc(offerChildren, selfLidJid);
  //   const key = enc ? await decryptInboundCallKey(sock, enc, parseInboundOfferLid(offer)) : null;
  //   if (key) { voip.setE2ECallKey(key, selfLidJid, peerLid); voip.handleSignalingMessage({ payload: offerXml }); /* → send <accept> */ }
  //
  (sock.ws as any).on("CB:call", (node: BinaryNode) => {
    const child = getAllBinaryNodeChildren(node)[0];
    if (!child) return;
    try {
      voip.handleSignalingMessage({ payload: binaryNodeToString(child) });
    } catch (err) {
      console.warn(`[voip] ingest failed for ${child.tag}:`, (err as Error).message);
    }
  });

  return { placeCall, endCall, voip };
}

// --- self-test wiring (delete when embedding) ---
if (import.meta.url === `file://${process.argv[1]}`) {
  const { useMultiFileAuthState, makeWASocket } = await import("@whiskeysockets/baileys");
  const { state, saveCreds } = await useMultiFileAuthState("./auth");
  const sock = makeWASocket({ auth: state, printQRInTerminal: true });
  sock.ev.on("creds.update", saveCreds);
  sock.ev.on("connection.update", async (u: any) => {
    if (u.connection !== "open") return;
    const calling = await attachCalling(sock);
    console.log("calling attached — run: calling.placeCall('15551234567')");
  });
}
