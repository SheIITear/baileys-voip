/**
 * WhatsApp call signaling helpers — Baileys/XMPP bridge.
 *
 * Reusable primitives any WhatsApp call implementation needs: JID parsing,
 * BinaryNode XML rendering, Signal-encrypted call-key handling, offer/acceptor
 * stanza construction, relay latency encoding, and session pre-warming.
 *
 * All functions are pure: state flows through parameters, no module-level
 * side effects. Every function that needs a WASocket receives it explicitly.
 */

import {
  decodeBinaryNode,
  encodeBinaryNode,
  encodeWAMessage,
  getAllBinaryNodeChildren,
  jidDecode,
  jidEncode,
  parseAndInjectE2ESessions,
  type BinaryNode,
} from "@whiskeysockets/baileys";

import type { SignalingMessage } from "../core/types";

// ---------------------------------------------------------------------------
// JID helpers
// ---------------------------------------------------------------------------

export const toBareJid = (jid: string): string => {
  const decoded = jidDecode(jid);
  if (!decoded?.user) {
    return jid;
  }
  const server = jid.endsWith("@lid") ? "lid" : "s.whatsapp.net";
  return jidEncode(decoded.user, server as any);
};

export const toCallDeviceJid = (jid: string): string => {
  const decoded = jidDecode(jid);
  if (!decoded?.user) {
    return jid;
  }
  const server = jid.endsWith("@lid") ? "lid" : "s.whatsapp.net";
  if (decoded.device === undefined || decoded.device === null) {
    return jidEncode(decoded.user, server as any);
  }
  return `${decoded.user}:${decoded.device}@${server}`;
};

export const toPrimaryDeviceJid = (jid: string): string | undefined => {
  const decoded = jidDecode(jid);
  if (!decoded?.user || decoded.device === undefined || decoded.device === null || decoded.device === 0) {
    return undefined;
  }
  const server = jid.endsWith("@lid") ? "lid" : "s.whatsapp.net";
  return jidEncode(decoded.user, server as any);
};

export const jidBaseUser = (jid: string): string =>
  (jid.split("@")[0] ?? "").split(":")[0] ?? "";

// ---------------------------------------------------------------------------
// BinaryNode <-> string rendering
// ---------------------------------------------------------------------------

export const binaryNodeToString = (node: BinaryNode): string => {
  try {
    const { binaryNodeToString: helper } = require("@whiskeysockets/baileys");
    return helper(node);
  } catch {
    return renderNodeFallback(node);
  }
};

export const renderNodeFallback = (node: BinaryNode): string => {
  const attrs = Object.entries(node.attrs || {})
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => ` ${k}="${String(v).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;")}"`)
    .join("");
  if (Array.isArray(node.content)) {
    const inner = node.content.map((c) => renderNodeFallback(c)).join("");
    return `<${node.tag}${attrs}>${inner}</${node.tag}>`;
  }
  if (node.content instanceof Uint8Array || Buffer.isBuffer(node.content as any)) {
    const buf = Buffer.isBuffer(node.content) ? node.content : Buffer.from(node.content as Uint8Array);
    return `<${node.tag}${attrs}>${buf.toString("hex")}</${node.tag}>`;
  }
  return `<${node.tag}${attrs}/>`;
};

// ---------------------------------------------------------------------------
// Signal session management
// ---------------------------------------------------------------------------

export const ensureSessions = async (
  sock: { signalRepository?: any; query?: Function },
  jids: string[],
  ensuredSessions: Set<string>,
  sWhatsappNet: string,
): Promise<void> => {
  const missing: string[] = [];
  for (const jid of jids.filter(Boolean)) {
    const sigId = sock.signalRepository!.jidToSignalProtocolAddress(jid);
    if (ensuredSessions.has(sigId)) continue;
    const validation = await sock.signalRepository!.validateSession(jid);
    if (validation.exists) {
      ensuredSessions.add(sigId);
      continue;
    }
    missing.push(jid);
  }
  if (!missing.length) return;
  const sessionNode = await sock.query!({
    tag: "iq",
    attrs: { xmlns: "encrypt", type: "get", to: sWhatsappNet },
    content: [{ tag: "key", attrs: {}, content: missing.map((jid) => ({ tag: "user", attrs: { jid } })) }],
  });
  await parseAndInjectE2ESessions(sessionNode, sock.signalRepository);
  for (const jid of missing) {
    ensuredSessions.add(sock.signalRepository!.jidToSignalProtocolAddress(jid));
  }
};

// ---------------------------------------------------------------------------
// Call key encryption / decryption
// ---------------------------------------------------------------------------

export const encryptCallKeyForJid = async (
  sock: { signalRepository?: { encryptMessage?: Function; jidToSignalProtocolAddress?: Function }; authState?: { creds?: { account?: any } } },
  targetJid: string,
  callKey: Uint8Array,
  count: number,
): Promise<BinaryNode> => {
  const { type, ciphertext } = await sock.signalRepository!.encryptMessage!({
    jid: targetJid,
    data: encodeWAMessage({ call: { callKey: Buffer.from(callKey) } }),
  });
  return {
    tag: "enc",
    attrs: { v: "2", type, count: String(count) },
    content: Buffer.from(ciphertext),
  };
};

export const decryptInboundCallKey = async (
  sock: { signalRepository?: { decryptMessage?: Function } },
  encNode: BinaryNode,
  senderJid: string,
): Promise<Uint8Array | null> => {
  try {
    const encType = String(encNode.attrs?.type ?? "msg");
    const ciphertext = encNode.content instanceof Uint8Array ? encNode.content : Buffer.from(encNode.content as any);
    const dec = await sock.signalRepository!.decryptMessage!({
      jid: senderJid,
      type: encType as "msg" | "pkmsg",
      ciphertext,
    });
    let unpadded = new Uint8Array(dec);
    if (unpadded.length > 0) {
      const padLen = unpadded[unpadded.length - 1]!;
      if (padLen > 0 && padLen <= 16 && padLen < unpadded.length) {
        unpadded = unpadded.slice(0, unpadded.length - padLen);
      }
    }
    const Message = (await import("@whiskeysockets/baileys/WAProto")).proto.Message as any;
    const msg = Message.decode(unpadded);
    const callKey = msg.call?.callKey as Uint8Array | undefined;
    if (callKey?.length === 32) return callKey;
    return null;
  } catch {
    return null;
  }
};

// ---------------------------------------------------------------------------
// Offer stanza helpers
// ---------------------------------------------------------------------------

export const parseInboundOfferLid = (child: BinaryNode): string => {
  const raw = String(child.attrs?.["call-creator"] ?? "");
  return toBareJid(raw);
};

export const extractOfferEnc = (
  sigChildren: BinaryNode[],
  selfLidJid: string,
): BinaryNode | null => {
  const direct = sigChildren.find((c) => c.tag === "enc");
  if (direct) return direct;
  const dest = sigChildren.find((c) => c.tag === "destination");
  if (!dest) return null;
  const toNodes = (dest.content as BinaryNode[]) ?? [];
  const ourBare = jidBaseUser(selfLidJid).toLowerCase();
  for (const to of toNodes) {
    const tjid = String(to.attrs?.jid ?? "").toLowerCase();
    if (tjid === selfLidJid.toLowerCase() || jidBaseUser(tjid) === ourBare) {
      const enc = ((to.content as BinaryNode[]) ?? []).find((c) => c.tag === "enc");
      if (enc) return enc;
    }
  }
  for (const to of toNodes) {
    const tjid = String(to.attrs?.jid ?? "");
    if (!tjid.includes(":")) {
      const enc = ((to.content as BinaryNode[]) ?? []).find((c) => c.tag === "enc");
      if (enc) return enc;
    }
  }
  return null;
};

// ---------------------------------------------------------------------------
// Build offer stanza
// ---------------------------------------------------------------------------

export const buildOfferStanza = async (
  encryptCallKey: (targetJid: string, callKey: Uint8Array, count: number) => Promise<BinaryNode>,
  callId: string,
  selfLidJid: string,
  peerLidJid: string,
  peerDeviceJids: string[],
  sharedCallKey: Uint8Array,
  privacyHex?: string,
  capabilityHex?: string,
): Promise<{ offer: BinaryNode; routeTo: string; includeDeviceIdentity: boolean }> => {
  const targetJid = peerLidJid;
  const encNode = await encryptCallKey(targetJid, sharedCallKey, 0);
  const includeDeviceIdentity = encNode.attrs?.type === "pkmsg";

  const destinationChildren: BinaryNode[] = [];
  for (const deviceJid of peerDeviceJids.length ? peerDeviceJids : [toBareJid(peerLidJid)]) {
    const devEnc = await encryptCallKey(deviceJid, sharedCallKey, 0);
    destinationChildren.push({
      tag: "to",
      attrs: { jid: deviceJid },
      content: [devEnc],
    });
  }

  const offer: BinaryNode = {
    tag: "offer",
    attrs: {
      "call-id": callId,
      "call-creator": selfLidJid,
    },
    content: [
      { tag: "privacy", attrs: {}, content: Buffer.from(privacyHex || "04012bd2d6ddbcc7ddc12c", "hex") },
      { tag: "audio", attrs: { enc: "opus", rate: "8000" } },
      { tag: "audio", attrs: { enc: "opus", rate: "16000" } },
      { tag: "net", attrs: { medium: "3" } },
      { tag: "capability", attrs: { ver: "1" }, content: Buffer.from(capabilityHex || "0105f709e4bb13", "hex") },
      { tag: "destination", attrs: {}, content: destinationChildren },
      { tag: "encopt", attrs: { keygen: "2" } },
    ],
  };
  return { offer, routeTo: targetJid, includeDeviceIdentity };
};

export const appendDeviceIdentity = async (
  sock: { authState?: { creds?: { account?: any } } },
  offer: BinaryNode,
): Promise<void> => {
  try {
    const { encodeSignedDeviceIdentity } = await import("@whiskeysockets/baileys");
    const account = sock.authState?.creds?.account;
    if (!account) return;
    const deviceIdentity = encodeSignedDeviceIdentity(account, true);
    const children = Array.isArray(offer.content) ? offer.content : [];
    children.push({
      tag: "device-identity",
      attrs: {},
      content: deviceIdentity,
    } as BinaryNode);
    offer.content = children;
  } catch {}
};

// ---------------------------------------------------------------------------
// Send a call stanza and wait for ack, forwarding response to engine
// ---------------------------------------------------------------------------

export const sendCallStanza = async (
  sock: { sendNode?: Function; generateMessageTag?: Function; waitForMessage?: Function },
  engine: { handleSignalingAck: (msg: SignalingMessage) => void },
  routeTo: string,
  voipNode: BinaryNode,
  signalingTag: string,
  onAck?: (ackNode: BinaryNode, stanzaId: string) => void,
): Promise<void> => {
  const stanzaId = (sock.generateMessageTag as Function)();
  const callStanza: BinaryNode = {
    tag: "call",
    attrs: { to: routeTo, id: stanzaId },
    content: [voipNode],
  };
  await (sock.sendNode as Function)(callStanza);
  void (async () => {
    try {
      const ackNode = await (sock.waitForMessage as Function)(stanzaId, 15_000);
      if (ackNode) {
        const ackError = ackNode.attrs?.error ?? "0";
        const ackType = ackNode.attrs?.type ?? "";
        const innerAck = getAllBinaryNodeChildren(ackNode)[0] ?? ackNode;
        engine.handleSignalingAck({
          payload: binaryNodeToString(innerAck),
          ackError,
          msgType: ackType || signalingTag,
          peerJid: routeTo,
        });
        onAck?.(ackNode, stanzaId);
      }
    } catch {}
  })();
};

// ---------------------------------------------------------------------------
// Relay latency encoding
// ---------------------------------------------------------------------------

export const encodeRelayLatencyValue = (rttMs: number | null): number => {
  const lo = Math.max(1, Math.min(0xffff, Math.round((rttMs ?? 30))));
  return (0x02000000 | lo) >>> 0;
};

export const buildTeBody = (ip: string, port: number): Buffer => {
  const parts = ip.split(".").map((x) => parseInt(x, 10) & 0xff);
  const buf = Buffer.alloc(6);
  buf[0] = parts[0] ?? 0; buf[1] = parts[1] ?? 0; buf[2] = parts[2] ?? 0; buf[3] = parts[3] ?? 0;
  buf.writeUInt16BE(port & 0xffff, 4);
  return buf;
};
