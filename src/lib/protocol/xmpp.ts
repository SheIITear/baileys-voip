/**
 * ============================================================================
 * STACK LAYER 7 — Call signaling (XMPP parser/builder)
 * ============================================================================
 *
 * Parses and builds the WhatsApp call stanzas: offer / preaccept / accept / ack /
 * terminate / reject, plus the embedded relay `<transport>` info and raw_e2e
 * material.
 *
 * Why: the call is negotiated entirely over these stanzas; relay credentials and
 * E2E keys arrive here. Hands off: relay info -> relayTransport (layer 2); keys ->
 * srtp1to1/sframe (layer 3); lifecycle events -> WhatsAppVoipNode.
 */
/**
 * XMPP signaling parser for WhatsApp VoIP call stanzas.
 *
 * Parses and builds the XML-based signaling protocol WhatsApp uses for call
 * setup and teardown: offer, preaccept, accept, ack, lobby_ack, link_join_ack,
 * terminate, and reject stanzas. Also parses embedded relay transport info
 * (connection ID, tokens, endpoint lists) and group info. Includes a tiny
 * XML parser (no external dependencies) and XML renderer for building
 * well-formed XMPP nodes from typed data.
 */

import { Buffer } from "node:buffer";

export interface XmlAttr {
  name: string;
  value: string;
}

export interface ExtraXmlNode {
  tag: string;
  attrs: XmlAttr[];
  text: string;
  children: ExtraXmlNode[];
}

export interface TransportEndpoint {
  host: string;
  port: number;
  rawContent: string;
  relayId: string;
  tokenId: string;
  authTokenId: string;
  relayName: string;
  protocol: string;
}

export interface RelayToken {
  id: string;
  value: string;
}

export interface RelayParticipantInfo {
  pid: number;
  jid: string;
  extraChildren: ExtraXmlNode[];
}

export interface TransportInfo {
  connId: string;
  key: string;
  token: string;
  authToken: string;
  hbhKey: string;
  warpMiTagLen: number;
  preferRelay: boolean;
  peerDl: boolean;
  preferIpv6: boolean;
  smartTransportSignal: string;
  xtokenId: number;
  authTokenId: number;
  c2rRtt: number;
  relayName: string;
  domainName: string;
  te: TransportEndpoint[];
  te2: TransportEndpoint[];
  tokens: RelayToken[];
  authTokens: RelayToken[];
  extraChildren: ExtraXmlNode[];
}

export interface RelayInfo {
  attrs: XmlAttr[];
  peerPid: number;
  selfPid: number;
  uuid: string;
  participants: RelayParticipantInfo[];
  transport: TransportInfo;
  extraChildren: ExtraXmlNode[];
}

export interface Capability {
  version: number;
}

export interface MediaFlags {
  audio: boolean;
  video: boolean;
  screenShare: boolean;
  appData: boolean;
}

export interface Participant {
  pid: number;
  state: string;
  deviceJid: string;
  capability?: Capability;
  media: MediaFlags;
  extraChildren: ExtraXmlNode[];
}

export interface GroupInfo {
  connectedLimit: number;
  participants: Participant[];
  extraChildren: ExtraXmlNode[];
}

export interface OfferStanza {
  callId: string;
  callCreator: string;
  callerPn: string;
  callerCountryCode: string;
  joinable: boolean;
  transactionId: string;
  phash: string;
  state: string;
  relay?: RelayInfo;
  groupInfo?: GroupInfo;
  voipSettings: ExtraXmlNode[];
  extensionInfo: ExtraXmlNode[];
  linkInfo: ExtraXmlNode[];
  rekey: ExtraXmlNode[];
  extraChildren: ExtraXmlNode[];
}

export interface PreacceptStanza {
  callId: string;
  callCreator: string;
  transactionId: string;
  deviceJid: string;
  audioCaps: string;
  videoCaps: string;
  extraChildren: ExtraXmlNode[];
}

export interface AcceptStanza {
  callId: string;
  callCreator: string;
  transactionId: string;
  deviceJid: string;
  rawE2E: string;
  certFingerprintHmacAlg: string;
  certFingerprintHmac: string;
  relay?: RelayInfo;
  groupInfo?: GroupInfo;
  extraChildren: ExtraXmlNode[];
}

export interface LobbyAckStanza {
  callId: string;
  transactionId: string;
  groupInfo?: GroupInfo;
  errorCode: string;
  extraChildren: ExtraXmlNode[];
}

export interface LinkJoinAckStanza {
  callId: string;
  callCreator: string;
  token: string;
  transactionId: string;
  voipSettings: ExtraXmlNode[];
  groupInfo?: GroupInfo;
  errorCode: string;
  extraChildren: ExtraXmlNode[];
}

export interface AckStanza {
  callId: string;
  callCreator: string;
  ackType: string;
  errorCode: string;
  relay?: RelayInfo;
  voipSettings: ExtraXmlNode[];
  extraChildren: ExtraXmlNode[];
}

export interface TerminateStanza {
  callId: string;
  callCreator: string;
  reason: string;
  extraChildren: ExtraXmlNode[];
}

export interface RejectStanza {
  callId: string;
  callCreator: string;
  reason: string;
  extraChildren: ExtraXmlNode[];
}

export type StanzaEnvelope =
  | { kind: "offer"; sourceXml: string; offer: OfferStanza }
  | { kind: "preaccept"; sourceXml: string; preaccept: PreacceptStanza }
  | { kind: "accept"; sourceXml: string; accept: AcceptStanza }
  | { kind: "lobby_ack"; sourceXml: string; lobbyAck: LobbyAckStanza }
  | { kind: "link_join_ack"; sourceXml: string; linkJoinAck: LinkJoinAckStanza }
  | { kind: "ack"; sourceXml: string; ack: AckStanza }
  | { kind: "terminate"; sourceXml: string; terminate: TerminateStanza }
  | { kind: "reject"; sourceXml: string; reject: RejectStanza }
  | { kind: "relay"; sourceXml: string; relay: RelayInfo; callId: string };

interface XmlNode {
  tag: string;
  attrs: Record<string, string>;
  children: XmlNode[];
  textParts: string[];
}

const xmlEntityMap: Record<string, string> = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: "\"",
  apos: "'",
};

const decodeEntities = (value: string): string =>
  value.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (_match, entity: string) => {
    if (entity.startsWith("#x")) {
      return String.fromCodePoint(Number.parseInt(entity.slice(2), 16));
    }
    if (entity.startsWith("#")) {
      return String.fromCodePoint(Number.parseInt(entity.slice(1), 10));
    }
    return xmlEntityMap[entity] ?? `&${entity};`;
  });

const parseAttributes = (source: string): Record<string, string> => {
  const attrs: Record<string, string> = {};
  const attrPattern =
    /([A-Za-z_][A-Za-z0-9_:\-.]*)\s*=\s*("([^"]*)"|'([^']*)')/g;
  let match: RegExpExecArray | null;
  while ((match = attrPattern.exec(source)) !== null) {
    attrs[match[1]!] = decodeEntities(match[3] ?? match[4] ?? "");
  }
  return attrs;
};

const parseXml = (xml: string): XmlNode => {
  const tokenPattern =
    /<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<!\[CDATA\[[\s\S]*?\]\]>|<\/?[^>]+>|[^<]+/g;
  const stack: XmlNode[] = [];
  let root: XmlNode | null = null;
  const tokens = xml.match(tokenPattern) ?? [];

  for (const token of tokens) {
    if (!token) {
      continue;
    }

    if (token.startsWith("<!--") || token.startsWith("<?")) {
      continue;
    }

    if (token.startsWith("<![CDATA[")) {
      const text = token.slice(9, -3);
      if (stack.length > 0) {
        stack[stack.length - 1]!.textParts.push(text);
      }
      continue;
    }

    if (token.startsWith("</")) {
      const tag = token.slice(2, -1).trim();
      const current = stack.pop();
      if (!current || current.tag !== tag) {
        throw new Error(`unexpected closing tag: ${tag}`);
      }
      continue;
    }

    if (token.startsWith("<")) {
      const selfClosing = token.endsWith("/>");
      const content = token.slice(1, selfClosing ? -2 : -1).trim();
      const spaceIndex = content.search(/\s/);
      const tag = (spaceIndex === -1 ? content : content.slice(0, spaceIndex)).trim();
      const attrSource = spaceIndex === -1 ? "" : content.slice(spaceIndex + 1);
      const node: XmlNode = {
        tag,
        attrs: parseAttributes(attrSource),
        children: [],
        textParts: [],
      };
      if (stack.length > 0) {
        stack[stack.length - 1]!.children.push(node);
      } else {
        root = node;
      }
      if (!selfClosing) {
        stack.push(node);
      }
      continue;
    }

    if (stack.length > 0) {
      const text = decodeEntities(token);
      if (text.trim().length > 0) {
        stack[stack.length - 1]!.textParts.push(text);
      }
    }
  }

  if (!root || stack.length !== 0) {
    throw new Error("invalid XML payload");
  }

  return root;
};

const attrsOf = (node: XmlNode): XmlAttr[] =>
  Object.entries(node.attrs).map(([name, value]) => ({ name, value }));

const innerText = (node: XmlNode): string =>
  [...node.textParts, ...node.children.map((child) => innerText(child))]
    .join("")
    .trim();

const childElements = (node: XmlNode, name: string): XmlNode[] =>
  node.children.filter((child) => child.tag === name);

const maybeInt = (value: string | undefined): number => {
  if (!value) {
    return 0;
  }
  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) ? 0 : parsed;
};

const maybeBool = (value: string | undefined): boolean => {
  const normalized = (value ?? "").trim().toLowerCase();
  return normalized === "1" || normalized === "true";
};

const toExtra = (node: XmlNode): ExtraXmlNode => ({
  tag: node.tag,
  attrs: attrsOf(node),
  text: innerText(node),
  children: node.children.map((child) => toExtra(child)),
});

const parseEndpoint = (node: XmlNode): TransportEndpoint => ({
  host: node.attrs.addr ?? node.attrs.domain_name ?? "",
  port: maybeInt(node.attrs.port),
  rawContent: innerText(node),
  relayId: node.attrs.relay_id ?? "",
  tokenId: node.attrs.token_id ?? node.attrs.xtoken_id ?? "",
  authTokenId: node.attrs.auth_token_id ?? "",
  relayName: node.attrs.relay_name ?? "",
  protocol: node.attrs.protocol ?? "",
});

const parseEndpointList = (node: XmlNode): TransportEndpoint[] => {
  const endpoints = childElements(node, "endpoint");
  if (endpoints.length > 0) {
    return endpoints.map((endpoint) => parseEndpoint(endpoint));
  }
  return [parseEndpoint(node)];
};

const createEmptyTransport = (): TransportInfo => ({
  connId: "",
  key: "",
  token: "",
  authToken: "",
  hbhKey: "",
  warpMiTagLen: 0,
  preferRelay: false,
  peerDl: false,
  preferIpv6: false,
  smartTransportSignal: "",
  xtokenId: 0,
  authTokenId: 0,
  c2rRtt: 0,
  relayName: "",
  domainName: "",
  te: [],
  te2: [],
  tokens: [],
  authTokens: [],
  extraChildren: [],
});

const transportFieldTags = new Set([
  "conn_id",
  "key",
  "token",
  "auth_token",
  "hbh_key",
  "warp_mi_tag_len",
  "prefer_relay",
  "peer_dl",
  "prefer_ipv6",
  "smart_transport_signal",
  "xtoken_id",
  "auth_token_id",
  "c2r_rtt",
  "relay_name",
  "domain_name",
  "te",
  "te2",
]);

const applyTransportChild = (result: TransportInfo, child: XmlNode): boolean => {
  switch (child.tag) {
    case "conn_id":
      result.connId = innerText(child);
      return true;
    case "key":
      result.key = innerText(child);
      return true;
    case "token": {
      const value = innerText(child);
      if (!result.token) {
        result.token = value;
      }
      result.tokens.push({
        id: child.attrs.id ?? child.attrs.token_id ?? "",
        value,
      });
      return true;
    }
    case "auth_token": {
      const value = innerText(child);
      if (!result.authToken) {
        result.authToken = value;
      }
      result.authTokens.push({
        id: child.attrs.id ?? child.attrs.auth_token_id ?? "",
        value,
      });
      return true;
    }
    case "hbh_key":
      result.hbhKey = innerText(child);
      return true;
    case "warp_mi_tag_len":
      result.warpMiTagLen = maybeInt(innerText(child));
      return true;
    case "prefer_relay":
      result.preferRelay = maybeBool(innerText(child));
      return true;
    case "peer_dl":
      result.peerDl = maybeBool(innerText(child));
      return true;
    case "prefer_ipv6":
      result.preferIpv6 = maybeBool(innerText(child));
      return true;
    case "smart_transport_signal":
      result.smartTransportSignal = innerText(child);
      return true;
    case "xtoken_id":
      result.xtokenId = maybeInt(innerText(child));
      return true;
    case "auth_token_id":
      result.authTokenId = maybeInt(innerText(child));
      return true;
    case "c2r_rtt":
      result.c2rRtt = maybeInt(innerText(child));
      return true;
    case "relay_name":
      result.relayName = innerText(child);
      return true;
    case "domain_name":
      result.domainName = innerText(child);
      return true;
    case "te":
      result.te.push(...parseEndpointList(child));
      return true;
    case "te2":
      result.te2.push(...parseEndpointList(child));
      return true;
    default:
      return false;
  }
};

const parseTransport = (node: XmlNode): TransportInfo => {
  const result = createEmptyTransport();

  for (const child of node.children) {
    if (!applyTransportChild(result, child)) {
      result.extraChildren.push(toExtra(child));
    }
  }

  if (result.te.length > 0 && result.te2.length > 0) {
    throw new Error("can not receive both te and te2 endpoints");
  }

  return result;
};

const parseRelayParticipant = (node: XmlNode): RelayParticipantInfo => ({
  pid: maybeInt(node.attrs.pid),
  jid: node.attrs.jid ?? "",
  extraChildren: node.children.map((child) => toExtra(child)),
});

const parseRelay = (node: XmlNode): RelayInfo => {
  let transport: TransportInfo | undefined;
  const participants: RelayParticipantInfo[] = [];
  const extraChildren: ExtraXmlNode[] = [];
  for (const child of node.children) {
    if (child.tag === "transport") {
      transport = parseTransport(child);
      continue;
    }
    if (child.tag === "participant") {
      participants.push(parseRelayParticipant(child));
      continue;
    }
    if (transportFieldTags.has(child.tag)) {
      transport ??= createEmptyTransport();
      applyTransportChild(transport, child);
      continue;
    }
    if (child.tag === "token" || child.tag === "auth_token") {
      transport ??= createEmptyTransport();
      applyTransportChild(transport, child);
      continue;
    }
    extraChildren.push(toExtra(child));
  }

  if (!transport) {
    throw new Error("relay stanza missing transport");
  }

  return {
    attrs: attrsOf(node),
    peerPid: maybeInt(node.attrs.peer_pid),
    selfPid: maybeInt(node.attrs.self_pid),
    uuid: node.attrs.uuid ?? "",
    participants,
    transport,
    extraChildren,
  };
};

const parseMedia = (node: XmlNode): MediaFlags => {
  const result: MediaFlags = {
    audio: false,
    video: false,
    screenShare: false,
    appData: false,
  };
  for (const child of node.children) {
    switch (child.tag) {
      case "audio":
        result.audio = true;
        break;
      case "video":
        result.video = true;
        break;
      case "screen_share":
        result.screenShare = true;
        break;
      case "app_data":
        result.appData = true;
        break;
      default:
        break;
    }
  }
  return result;
};

const parseParticipant = (node: XmlNode): Participant => {
  const participant: Participant = {
    pid: maybeInt(node.attrs.pid),
    state: node.attrs.state ?? "",
    deviceJid: "",
    media: {
      audio: false,
      video: false,
      screenShare: false,
      appData: false,
    },
    extraChildren: [],
  };

  for (const child of node.children) {
    switch (child.tag) {
      case "device":
        participant.deviceJid = child.attrs.jid ?? "";
        break;
      case "capability":
        participant.capability = {
          version: maybeInt(child.attrs.ver),
        };
        break;
      case "media":
        participant.media = parseMedia(child);
        break;
      default:
        participant.extraChildren.push(toExtra(child));
        break;
    }
  }

  return participant;
};

const parseGroupInfo = (node: XmlNode): GroupInfo => {
  const result: GroupInfo = {
    connectedLimit: maybeInt(node.attrs["connected-limit"]),
    participants: [],
    extraChildren: [],
  };

  for (const child of node.children) {
    if (child.tag === "participant") {
      result.participants.push(parseParticipant(child));
    } else {
      result.extraChildren.push(toExtra(child));
    }
  }

  return result;
};

const parseOffer = (node: XmlNode): OfferStanza => {
  const offer: OfferStanza = {
    callId: node.attrs["call-id"] ?? "",
    callCreator: node.attrs["call-creator"] ?? "",
    callerPn: node.attrs.caller_pn ?? "",
    callerCountryCode: node.attrs.caller_country_code ?? "",
    joinable: maybeBool(node.attrs.joinable),
    transactionId: node.attrs["transaction-id"] ?? "",
    phash: node.attrs.phash ?? "",
    state: node.attrs.state ?? "",
    voipSettings: [],
    extensionInfo: [],
    linkInfo: [],
    rekey: [],
    extraChildren: [],
  };

  for (const child of node.children) {
    switch (child.tag) {
      case "voip_settings":
        offer.voipSettings.push(toExtra(child));
        break;
      case "relay":
        offer.relay = parseRelay(child);
        break;
      case "group_info":
        offer.groupInfo = parseGroupInfo(child);
        break;
      case "extension_info":
        offer.extensionInfo.push(toExtra(child));
        break;
      case "link_info":
        offer.linkInfo.push(toExtra(child));
        break;
      case "rekey":
        offer.rekey.push(toExtra(child));
        break;
      default:
        offer.extraChildren.push(toExtra(child));
        break;
    }
  }

  return offer;
};

const parsePreaccept = (node: XmlNode): PreacceptStanza => {
  const stanza: PreacceptStanza = {
    callId: node.attrs["call-id"] ?? "",
    callCreator: node.attrs["call-creator"] ?? "",
    transactionId: node.attrs["transaction-id"] ?? "",
    deviceJid: "",
    audioCaps: "",
    videoCaps: "",
    extraChildren: [],
  };
  for (const child of node.children) {
    switch (child.tag) {
      case "device":
        stanza.deviceJid = child.attrs.jid ?? "";
        break;
      case "audio":
        if (child.attrs.caps != null) {
          stanza.audioCaps = child.attrs.caps;
        } else {
          stanza.extraChildren.push(toExtra(child));
        }
        break;
      case "video":
        if (child.attrs.caps != null) {
          stanza.videoCaps = child.attrs.caps;
        } else {
          stanza.extraChildren.push(toExtra(child));
        }
        break;
      default:
        stanza.extraChildren.push(toExtra(child));
        break;
    }
  }
  return stanza;
};

const parseAccept = (node: XmlNode): AcceptStanza => {
  const stanza: AcceptStanza = {
    callId: node.attrs["call-id"] ?? "",
    callCreator: node.attrs["call-creator"] ?? "",
    transactionId: node.attrs["transaction-id"] ?? "",
    deviceJid: "",
    rawE2E: "",
    certFingerprintHmacAlg: "",
    certFingerprintHmac: "",
    extraChildren: [],
  };
  for (const child of node.children) {
    switch (child.tag) {
      case "device":
        stanza.deviceJid = child.attrs.jid ?? "";
        break;
      case "raw_e2e":
        stanza.rawE2E = innerText(child);
        break;
      case "cert_fingerprint_hmac":
        stanza.certFingerprintHmacAlg = child.attrs.alg ?? "";
        stanza.certFingerprintHmac = innerText(child);
        break;
      case "relay":
        stanza.relay = parseRelay(child);
        break;
      case "group_info":
        stanza.groupInfo = parseGroupInfo(child);
        break;
      default:
        stanza.extraChildren.push(toExtra(child));
        break;
    }
  }
  return stanza;
};

const parseLobbyAck = (node: XmlNode): LobbyAckStanza => {
  const stanza: LobbyAckStanza = {
    callId: node.attrs["call-id"] ?? "",
    transactionId: node.attrs["transaction-id"] ?? "",
    errorCode: "",
    extraChildren: [],
  };
  for (const child of node.children) {
    switch (child.tag) {
      case "group_info":
        stanza.groupInfo = parseGroupInfo(child);
        break;
      case "error":
        stanza.errorCode = child.attrs.code ?? "";
        break;
      default:
        stanza.extraChildren.push(toExtra(child));
        break;
    }
  }
  return stanza;
};

const parseLinkJoinAck = (node: XmlNode): LinkJoinAckStanza => {
  const stanza: LinkJoinAckStanza = {
    callId: node.attrs["call-id"] ?? "",
    callCreator: node.attrs["call-creator"] ?? "",
    token: node.attrs.token ?? "",
    transactionId: node.attrs["transaction-id"] ?? "",
    voipSettings: [],
    errorCode: "",
    extraChildren: [],
  };
  for (const child of node.children) {
    switch (child.tag) {
      case "voip_settings":
        stanza.voipSettings.push(toExtra(child));
        break;
      case "group_info":
        stanza.groupInfo = parseGroupInfo(child);
        break;
      case "error":
        stanza.errorCode = child.attrs.code ?? "";
        break;
      default:
        stanza.extraChildren.push(toExtra(child));
        break;
    }
  }
  return stanza;
};

const parseAck = (node: XmlNode): AckStanza => {
  const stanza: AckStanza = {
    callId: "",
    callCreator: "",
    ackType: node.attrs.type ?? "",
    errorCode: node.attrs.error ?? "",
    voipSettings: [],
    extraChildren: [],
  };
  for (const child of node.children) {
    switch (child.tag) {
      case "relay":
        stanza.relay = parseRelay(child);
        stanza.callId =
          stanza.callId || child.attrs["call-id"] || child.attrs.call_id || "";
        stanza.callCreator =
          stanza.callCreator ||
          child.attrs["call-creator"] ||
          child.attrs.call_creator ||
          "";
        break;
      case "voip_settings":
        stanza.voipSettings.push(toExtra(child));
        break;
      default:
        stanza.extraChildren.push(toExtra(child));
        break;
    }
  }
  return stanza;
};

const parseTerminate = (node: XmlNode): TerminateStanza => ({
  callId: node.attrs["call-id"] || node.attrs.call_id || "",
  callCreator: node.attrs["call-creator"] || node.attrs.call_creator || "",
  reason: node.attrs.reason ?? "",
  extraChildren: node.children.map(toExtra),
});

const parseReject = (node: XmlNode): RejectStanza => ({
  callId: node.attrs["call-id"] || node.attrs.call_id || "",
  callCreator: node.attrs["call-creator"] || node.attrs.call_creator || "",
  reason: node.attrs.reason ?? "",
  extraChildren: node.children.map(toExtra),
});

export const parseStanza = (xml: string): StanzaEnvelope => {
  const node = parseXml(xml);
  switch (node.tag) {
    case "offer":
      return {
        kind: "offer",
        sourceXml: xml,
        offer: parseOffer(node),
      };
    case "preaccept":
      return {
        kind: "preaccept",
        sourceXml: xml,
        preaccept: parsePreaccept(node),
      };
    case "accept":
      return {
        kind: "accept",
        sourceXml: xml,
        accept: parseAccept(node),
      };
    case "lobby_ack":
      return {
        kind: "lobby_ack",
        sourceXml: xml,
        lobbyAck: parseLobbyAck(node),
      };
    case "link_join_ack":
      return {
        kind: "link_join_ack",
        sourceXml: xml,
        linkJoinAck: parseLinkJoinAck(node),
      };
    case "ack":
      return {
        kind: "ack",
        sourceXml: xml,
        ack: parseAck(node),
      };
    case "terminate":
      return {
        kind: "terminate",
        sourceXml: xml,
        terminate: parseTerminate(node),
      };
    case "reject":
      return {
        kind: "reject",
        sourceXml: xml,
        reject: parseReject(node),
      };
    case "relay":
      // Top-level <relay> envelope returned in the <call><ack> response to
      // an outgoing <offer>. Production WhatsApp drives the relay-list
      // update purely from this top-level relay block (the inner <accept>
      // stanza never carries one). We surface it here as a first-class
      // stanza kind so `WhatsAppVoipNode.handleSignalingAck` can apply it.
      return {
        kind: "relay",
        sourceXml: xml,
        relay: parseRelay(node),
        callId: node.attrs["call-id"] || node.attrs.call_id || "",
      };
    default:
      throw new Error(`unsupported stanza: ${node.tag}`);
  }
};

export const decodeSignalingXml = (payload: string | Uint8Array): string => {
  const raw =
    typeof payload === "string" ? payload.trim() : Buffer.from(payload).toString("utf8").trim();
  if (raw.startsWith("<")) {
    return raw;
  }

  const decoded = Buffer.from(raw, "base64").toString("utf8").trim();
  if (decoded.startsWith("<")) {
    return decoded;
  }

  return raw;
};

export type XmlAttrSource = XmlAttr[] | Record<string, string | number | boolean | undefined>;

export type XmlRenderable = ExtraXmlNode | string;

const escapeXmlText = (value: string): string =>
  value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

const escapeXmlAttr = (value: string): string =>
  escapeXmlText(value).replace(/"/g, "&quot;").replace(/'/g, "&apos;");

const normalizeAttrs = (attrs: XmlAttrSource = {}): XmlAttr[] =>
  Array.isArray(attrs)
    ? attrs
    : Object.entries(attrs)
        .filter(([, value]) => value !== undefined)
        .map(([name, value]) => ({ name, value: String(value) }));

export const extraXmlNode = (
  tag: string,
  attrs: XmlAttrSource = {},
  content: XmlRenderable[] = []
): ExtraXmlNode => {
  const textParts: string[] = [];
  const children: ExtraXmlNode[] = [];
  for (const item of content) {
    if (typeof item === "string") {
      textParts.push(item);
    } else {
      children.push(item);
    }
  }
  return {
    tag,
    attrs: normalizeAttrs(attrs),
    text: textParts.join(""),
    children,
  };
};

export const renderExtraXmlNode = (node: ExtraXmlNode): string => {
  const attrs = node.attrs
    .map((attr) => ` ${attr.name}="${escapeXmlAttr(attr.value)}"`)
    .join("");
  const childXml = node.children.map((child) => renderExtraXmlNode(child)).join("");
  const text = node.text ? escapeXmlText(node.text) : "";
  if (!text && !childXml) {
    return `<${node.tag}${attrs}/>`;
  }
  return `<${node.tag}${attrs}>${text}${childXml}</${node.tag}>`;
};

export const renderXmlNode = (
  tag: string,
  attrs: XmlAttrSource = {},
  content: XmlRenderable[] = []
): string => renderExtraXmlNode(extraXmlNode(tag, attrs, content));
