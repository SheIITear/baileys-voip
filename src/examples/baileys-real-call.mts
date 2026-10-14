/**
 * End-to-end reference caller. Bridges Baileys (WhatsApp login + stanza I/O) to
 * the WhatsAppVoipNode engine: resolves the peer, builds and Signal-encrypts
 * the offer stanza, forwards inbound call signaling into the engine, plumbs a
 * WebRTC relay transport, and renders progress through the CallTui.
 *
 * Usage:
 *   npx tsx src/examples/baileys-real-call.mts <authDir> [phoneNumber]
 *
 * Flags:
 *   --verbose, -v      disable live TUI, print raw engine logs
 *
 * @author ShellTear
 */
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";

import makeWASocket, {
  getAllBinaryNodeChildren,
  useMultiFileAuthState,
  type BinaryNode,
} from "@whiskeysockets/baileys";

import {
  WhatsAppVoipNode,
  CallTui,
  traceFlush,
  traceMarker,
} from "../index";
import {
  RelayRtcTransport,
  type RelayListUpdatePayload,
} from "../lib/relay/RelayRtcTransport.mts";
import {
  toBareJid,
  toCallDeviceJid,
  binaryNodeToString,
  ensureSessions,
  encryptCallKeyForJid,
  buildOfferStanza,
  appendDeviceIdentity,
  sendCallStanza,
  encodeRelayLatencyValue,
  buildTeBody,
} from "../lib/app/whatsapp-signaling";


const HERE = dirname(fileURLToPath(import.meta.url));
const NODE_LOAD_DIR = resolve(HERE, "../..");
const DEFAULT_AUTH_DIR = resolve(NODE_LOAD_DIR, "auth");
const DEFAULT_AUDIO_SOURCE = "lavfi:sine=frequency=440";
const DEFAULT_PHONE_NUMBER = process.env.CALL_PEER_NUMBER || "";
const DEFAULT_DURATION_MS = 30_000;
const S_WHATSAPP_NET = "@s.whatsapp.net";

const argv = process.argv.slice(2);
const flags = argv.filter((a) => a.startsWith("-"));
const positionals = argv.filter((a) => !a.startsWith("-"));
const authDir = positionals[0] || DEFAULT_AUTH_DIR;
const peerPhone = (positionals[1] || DEFAULT_PHONE_NUMBER).replace(/\D/g, "");
const durationMs = Number.parseInt(process.env.CALL_DURATION_MS || "", 10) || DEFAULT_DURATION_MS;
const audioSource = process.env.CALL_AUDIO_SOURCE || DEFAULT_AUDIO_SOURCE;

const VERBOSE =
  process.env.CALL_VERBOSE === "1" ||
  argv.includes("--verbose") ||
  argv.includes("-v");
if (!VERBOSE && process.env.CALL_DIAG === undefined) {
  process.env.CALL_DIAG = "0";
}

const tui = new CallTui({ target: (argv[1] || DEFAULT_PHONE_NUMBER), verbose: VERBOSE });

const log = (msg: string) => {
  if (tui.isLive()) tui.event(msg);
  else if (VERBOSE) console.log(`[real-call] ${msg}`);
};
const warn = (msg: string) => {
  if (tui.isLive()) tui.warn(msg);
  else console.warn(`[real-call] ${msg}`);
};
const fail = (msg: string) => {
  if (tui.isLive()) tui.fail(msg);
  else console.error(`[real-call] ${msg}`);
};
const debug = (msg: string) => {
  if (VERBOSE && !tui.isLive()) console.log(`[real-call] ${msg}`);
};

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

interface SilentLogger {
  trace: (...args: unknown[]) => void;
  debug: (...args: unknown[]) => void;
  info: (...args: unknown[]) => void;
  warn: (...args: unknown[]) => void;
  error: (...args: unknown[]) => void;
  fatal: (...args: unknown[]) => void;
  child: () => SilentLogger;
  level: string;
}
const silentLogger: SilentLogger = {
  trace: () => {},
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
  fatal: () => {},
  child: () => silentLogger,
  level: "silent",
};

const main = async (): Promise<number> => {
  if (!existsSync(authDir)) {
    fail(`auth dir not found: ${authDir}`);
    return 2;
  }
  log(`auth=${authDir} peer=${peerPhone} duration=${durationMs}ms audio=${audioSource}`);

  const { state, saveCreds } = await useMultiFileAuthState(authDir);
  const sock = makeWASocket({
    auth: state,
    logger: silentLogger as any,
    printQRInTerminal: false,
    syncFullHistory: false,
    markOnlineOnConnect: false,
    generateHighQualityLinkPreview: false,
  });
  sock.ev.on("creds.update", saveCreds);

  await new Promise<void>((res, rej) => {
    let opened = false;
    sock.ev.on("connection.update", (update: any) => {
      if (update.connection === "open") {
        opened = true;
        res();
      } else if (update.connection === "close") {
        if (!opened) rej(new Error(`socket closed before opening: ${JSON.stringify(update.lastDisconnect?.error?.message ?? "")}`));
      }
    });
  });
  tui.start();
  tui.phase("connecting", "resolving peer");
  log("baileys connected");

  const selfPnJid = String(sock.authState.creds.me?.id ?? "");
  const selfLidJid = String(sock.authState.creds.me?.lid ?? "");
  log(`self pn=${selfPnJid} lid=${selfLidJid}`);
  tui.identity({ selfLid: selfLidJid });

  const peerPnJid = `${peerPhone}@s.whatsapp.net`;
  let peerLidJid = await sock.signalRepository?.lidMapping
    ?.getLIDForPN?.(peerPnJid)
    .catch(() => undefined as string | undefined) ?? "";
  if (!peerLidJid) {
    fail(`could not resolve LID for ${peerPnJid}`);
    sock.end(undefined);
    return 3;
  }
  log(`peer pn=${peerPnJid} lid=${peerLidJid}`);
  tui.identity({ peerLid: peerLidJid });

  const devices = await sock.getUSyncDevices([peerLidJid], true, false);
  let peerDeviceJids = devices.map((d: any) => String(d.jid)).filter(Boolean);
  if (process.env.TARGET_DEVICE) {
    const want = process.env.TARGET_DEVICE;
    const filtered = peerDeviceJids.filter((j: string) => new RegExp(`:${want}@`).test(j));
    if (filtered.length) { peerDeviceJids = filtered; log(`TARGET_DEVICE=${want} -> only ${JSON.stringify(filtered)}`); }
    else log(`TARGET_DEVICE=${want} not found among ${JSON.stringify(peerDeviceJids)}; using all`);
  }
  log(`peer devices: ${JSON.stringify(peerDeviceJids)}`);

  const ensuredSessions = new Set<string>();
  await ensureSessions(sock, [peerLidJid, ...peerDeviceJids], ensuredSessions, S_WHATSAPP_NET);
  log("signal sessions ensured");

  // -----------------------------------------------------------------------
  // VoIP engine + transport
  // -----------------------------------------------------------------------
  let voip!: WhatsAppVoipNode;
  const relayTransport = new RelayRtcTransport({
    onTransportMessage: (data, ip, port) => {
      try { voip.feedRelayDatagram(new Uint8Array(data), ip, port); } catch (err) { warn(`feedRelayDatagram failed: ${(err as Error).message}`); }
    },
    onIceRtt: (rttMs, ip, port) => {
      tui.relay(`${ip}:${port}`, { ip, port, rttMs });
      if (!tui.isLive()) log(`ice-rtt ${ip}:${port} = ${rttMs}ms`);
    },
    onLog: (level, message, details) => {
      const d = details as any;
      if (d && (d.id || d.relay)) {
        tui.relay(String(d.id ?? d.relay), {
          name: d.relay ? String(d.relay) : undefined,
          state: d.state ? String(d.state) : (d.reason ? String(d.reason) : undefined),
        });
      }
      if (tui.isLive()) {
        if (level === "warn" || level === "error") tui.warn(`relay: ${message}`);
      } else {
        log(`relay-transport:${level} ${message} ${details ? JSON.stringify(details) : ""}`);
      }
    },
  });
  log(`wrtc relay transport initialised`);
  let receivedSamples = 0;
  let nonZeroSamples = 0;
  let connected = false;
  let ended = false;
  let acceptedFrom: string | undefined;

  const callId = randomBytes(16).toString("hex").toUpperCase();
  const sharedCallKey = randomBytes(32);

  voip = new WhatsAppVoipNode({
    useXmppOffer: false,
    audioSource,
    disableIpv6: true,
    callbacks: {
      onLog: (level, message) => {
        if (level === "warn" || level === "error") warn(`voip:${level} ${message}`);
        else if (process.env.CALL_VERBOSE === "1") log(`voip:${level} ${message}`);
      },
      onCallEvent: (eventType, eventData) => {
        const summary = eventData ? eventData.slice(0, 200) : "";
        log(`voip event ${eventType}: ${summary}`);
        if (eventType === 156 && eventData) {
          try {
            const payload = JSON.parse(eventData) as RelayListUpdatePayload;
            relayTransport.updateRelayList(payload);
          } catch (err) {
            warn(`failed to apply relay-list update: ${(err as Error).message}`);
          }
        }
        if (eventType === 100) {
          ended = true;
        }
      },
      onAudioPlaybackData: (samples) => {
        receivedSamples += samples.length;
        for (let i = 0; i < samples.length; i += 1) {
          if (Math.abs(samples[i]!) > 0.001) nonZeroSamples += 1;
        }
      },
    },
  });

  await voip.initialize();
  voip.initVoipStack(selfPnJid, toBareJid(selfPnJid), selfLidJid);
  voip.setRelaySendCallback((packet, ip, port) => {
    relayTransport.send(Buffer.from(packet), ip, port);
  });

  // -----------------------------------------------------------------------
  // Inbound call handling
  // -----------------------------------------------------------------------
  const SUPPORTED_INBOUND = new Set([
    "offer", "preaccept", "accept", "ack", "lobby_ack", "link_join_ack", "terminate", "reject",
  ]);

  const handleIncomingCall = (node: BinaryNode) => {
    const child = getAllBinaryNodeChildren(node)[0];
    if (!child) return;
    const icid = String(child.attrs?.["call-id"] ?? child.attrs?.call_id ?? "");
    const routineInbound = child.tag === "relaylatency";
    if (routineInbound) debug(`SIG<-XMPP tag=${child.tag} from=${node.attrs.from} callId=${icid}`);
    else log(`SIG<-XMPP tag=${child.tag} from=${node.attrs.from} callId=${icid}`);

    if (icid && icid !== callId) return;

    if (!SUPPORTED_INBOUND.has(String(child.tag))) {
      if (String(child.tag) === "relaylatency") {
        void sendRelayLatency();
      }
      return;
    }

    try {
      const xml = binaryNodeToString(child);

      if (child.tag === "preaccept") {
        if (!connected) tui.phase("ringing", "peer ringing");
        void sendRelayLatency();
      } else if (child.tag === "accept") {
        connected = true;
        acceptedFrom = String(node.attrs.from || "");
        tui.phase("active", "peer accepted");
        tui.event("peer accepted the call");
        log(`call active device locked to ${acceptedFrom || "(unknown)"}`);
      } else if (child.tag === "terminate" || child.tag === "reject") {
        const from = String(node.attrs.from || "");
        if (connected && acceptedFrom && from && from !== acceptedFrom) {
          log(`ignoring ${child.tag} from non-active device ${from}; active=${acceptedFrom}`);
          return;
        }
        ended = true;
        tui.phase("ended", "peer terminated");
      }
      voip.handleSignalingMessage({ payload: xml });
    } catch (err) {
      warn(`engine ingest failed for ${child.tag}: ${(err as Error).message}`);
    }
  };

  (sock.ws as any).on("CB:call", handleIncomingCall);

  // -----------------------------------------------------------------------
  // relaylatency helper
  // -----------------------------------------------------------------------
  let relayLatencySent = false;
  const sendRelayLatency = async (toTarget?: string): Promise<void> => {
    const relays = relayTransport
      .listRelayLatencies()
      .filter((r) => r.open && r.ip && !r.ip.includes(":"));
    if (relays.length === 0) {
      warn("relaylatency: no open relays to report yet");
      return;
    }
    const target = toTarget || peerLidJid;
    const destinationChildren: BinaryNode[] = (
      peerDeviceJids.length ? peerDeviceJids : [target]
    ).map((jid) => ({ tag: "to", attrs: { jid } } as BinaryNode));

    let first = !relayLatencySent;
    for (const relay of relays) {
      const teNode: BinaryNode = {
        tag: "te",
        attrs: {
          latency: String(encodeRelayLatencyValue(relay.rttMs)),
          relay_name: relay.name,
        },
        content: buildTeBody(relay.ip, relay.port),
      };
      const content: BinaryNode[] = [teNode];
      if (first) {
        content.push({ tag: "destination", attrs: {}, content: destinationChildren });
      }
      const relayLatencyNode: BinaryNode = {
        tag: "relaylatency",
        attrs: { "call-id": callId, "call-creator": selfLidJid },
        content,
      };
      const stanzaId = sock.generateMessageTag();
      const callStanza: BinaryNode = {
        tag: "call",
        attrs: { to: target, id: stanzaId },
        content: [relayLatencyNode],
      };
      try {
        await sock.sendNode(callStanza);
        debug(`SIG->XMPP tag=relaylatency relay=${relay.name} ip=${relay.ip}:${relay.port} rtt=${relay.rttMs ?? "?"} first=${first}`);
      } catch (err) {
        warn(`relaylatency send failed for ${relay.name}: ${(err as Error).message}`);
      }
      first = false;
    }
    relayLatencySent = true;
  };

  const encryptionWrapper = (targetJid: string, callKey: Uint8Array, count: number) =>
    encryptCallKeyForJid(sock, targetJid, callKey, count);

  // -----------------------------------------------------------------------
  // Place the call
  // -----------------------------------------------------------------------
  tui.phase("connecting", "placing call");
  tui.identity({ callId });
  log(`placing call: callId=${callId}`);
  traceMarker("real_call_start", { callId, peerPnJid, peerLidJid, audioSource, durationMs });
  voip.startCall({
    callId,
    peerJid: peerLidJid,
    peerPn: peerPnJid,
    isVideo: false,
  });

  voip.setE2ECallKey(sharedCallKey, selfLidJid, peerLidJid, peerDeviceJids);
  log(`E2E callKey=${sharedCallKey.toString('hex')} selfLid=${selfLidJid} peerLid=${peerLidJid} peerDevices=${JSON.stringify(peerDeviceJids)}`);
  try { tui.ssrcPlan(voip.getSenderSsrc(), voip.getExpectedPeerSsrcs()); } catch {}

  const { offer: offerNode, routeTo, includeDeviceIdentity } = await buildOfferStanza(
    encryptionWrapper,
    callId,
    selfLidJid,
    peerLidJid,
    peerDeviceJids,
    sharedCallKey,
    process.env.CALL_PRIVACY_HEX || undefined,
    process.env.CALL_CAPABILITY_HEX || undefined,
  );
  if (includeDeviceIdentity) {
    await appendDeviceIdentity(sock, offerNode);
  }
  await sendCallStanza(sock, voip, routeTo, offerNode, "offer");
  tui.phase(connected ? "active" : "ringing", "offer sent");
  tui.event("offer sent, waiting for accept");
  log("offer sent, waiting for accept...");

  const acceptWaitMs = Number.parseInt(process.env.CALL_ACCEPT_WAIT_MS || "", 10) || 60_000;
  const start = Date.now();
  while (!connected && !ended && Date.now() - start < acceptWaitMs) {
    await sleep(200);
  }
  if (!connected) {
    tui.phase("failed", ended ? "peer terminated" : "no accept");
    warn(`call did not connect within ${acceptWaitMs}ms; ${ended ? "peer terminated" : "no accept received"}`);
  } else {
    tui.setHold(durationMs);
    log(`call active, holding for ${durationMs}ms`);

    const muteNode: BinaryNode = {
      tag: "mute_v2",
      attrs: { "call-id": callId, "call-creator": selfLidJid, "mute-state": "0" },
    };
    await sendCallStanza(sock, voip, toCallDeviceJid(peerLidJid), muteNode, "mute_v2").catch(() => {});
    log("sent mute_v2 state=0 (unmuted)");

    const stop = Date.now() + durationMs;
    while (!ended && Date.now() < stop) {
      await sleep(1_000);
      const stats = voip.getMediaStats();
      tui.stats({ rtpSent: stats.rtpSent, rtpRecv: stats.rtpReceived, octRecv: stats.octetsReceived });
      tui.audio(receivedSamples, nonZeroSamples);
      tui.ssrcPlan(voip.getSenderSsrc(), voip.getExpectedPeerSsrcs());
      if (!tui.isLive()) log(`stats rtpSent=${stats.rtpSent} rtpRx=${stats.rtpReceived} octRx=${stats.octetsReceived} relays=${stats.relayControllerStates.length}`);
    }
  }

  // -----------------------------------------------------------------------
  // Teardown
  // -----------------------------------------------------------------------
  tui.phase("ending", "tearing down");
  if (!ended) {
    const terminateNode: BinaryNode = {
      tag: "terminate",
      attrs: { "call-id": callId, "call-creator": selfLidJid, reason: "accepted" },
    };
    await sendCallStanza(sock, voip, toCallDeviceJid(peerLidJid), terminateNode, "terminate").catch(() => {});
  }
  voip.endCall(0, false);
  voip.resetMedia("script-end");
  voip.destroy();

  await relayTransport.closeAll().catch(() => {});
  sock.end(undefined);

  try { const fs = voip.getMediaStats(); tui.stats({ rtpSent: fs.rtpSent, rtpRecv: fs.rtpReceived, octRecv: fs.octetsReceived }); } catch {}
  tui.audio(receivedSamples, nonZeroSamples);
  tui.phase("ended");
  tui.event(`done - sent media, received ${nonZeroSamples}/${receivedSamples} audio samples`);
  tui.stop();
  log(`final: receivedSamples=${receivedSamples} nonZeroSamples=${nonZeroSamples}`);
  traceMarker("real_call_end", { callId, receivedSamples, nonZeroSamples });
  traceFlush();
  return ended ? 0 : 1;
};

main()
  .then((code) => {
    setTimeout(() => process.exit(code), 500);
  })
  .catch((err) => {
    try { tui.stop(); } catch {}
    fail(`unhandled: ${err?.stack ?? String(err)}`);
    setTimeout(() => process.exit(1), 500);
  });
