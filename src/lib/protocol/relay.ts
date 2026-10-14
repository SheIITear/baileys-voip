/**
 * ============================================================================
 * STACK LAYER 2 — Relay control (STUN message layer)
 * ============================================================================
 *
 * Builds and parses the STUN messages that allocate and maintain a relay
 * session: Private Allocate (0x0003) with RELAY-TOKEN, STREAM-SUBSCRIPTION
 * (protobuf) and CONNECTION-ID attributes, binding responses, keepalive and
 * ping indications, all authenticated with a MESSAGE-INTEGRITY HMAC-SHA1.
 *
 * Why: a relay will not forward media until it has accepted an allocate and the
 * stream subscriptions match the SSRC plan. Hands off: messages are emitted
 * through the transport (layer 1) and consumed by relayController (the state
 * machine that decides when to send each one).
 */
/**
 * WhatsApp VoIP relay STUN message layer — allocate, bind, keepalive, ping.
 *
 * Builds and parses the proprietary STUN-based protocol WhatsApp uses for
 * relay signalling: private allocate requests (0x0003) with protobuf-encoded
 * stream subscription lists, relay token and CONNECTION-ID attributes,
 * binding requests/responses (0x0001/0x0101), keepalive indications (0x0801),
 * and relay ping requests (0x0804). All messages carry STUN MESSAGE-INTEGRITY
 * HMAC-SHA1 tags computed over the packet body with the relay transport key.
 */

import {
  concatBytes,
  readUint64BE,
  writeUint16BE,
  writeUint32BE,
} from "../core/bytes";
import { hmacSha1KeyFirst } from "../core/crypto";
import {
  parseStun,
  StunMagicCookie,
  type StunAttribute,
  type StunPacket,
} from "./protocol";

export const StunTypeBindingRequest = 0x0001;
export const StunTypePrivateAllocateRequest = 0x0003;
export const StunTypePrivateKeepaliveIndication = 0x0801;
export const StunTypePrivatePingRequest = 0x0804;
export const StunTypePrivatePingResponse = 0x0805;

export const StunAttrMessageIntegrity = 0x0008;
export const StunAttrConnectionId = 0x0016;
export const StunAttrRelayToken = 0x4000;
export const StunAttrRelayTimestamp = 0x4002;
export const StunAttrRelayPacketType = 0x4003;
export const StunAttrRelayPayload = 0x4004;
export const StunAttrRelayPingTimeout = 0x4007;
export const StunAttrStreamSubscription = 0x4024;

export interface RelayStreamSubscriptionEntry {
  participantIndex: number;
  streamIndex: number;
  ssrc: number;
}

export interface ParsedPrivateAllocateRequest {
  packet: StunPacket;
  relayToken: Uint8Array;
  streamSubscriptionRaw: Uint8Array;
  streamSubscriptions: RelayStreamSubscriptionEntry[];
  connIdData: Uint8Array;
  connId?: bigint;
  messageIntegrity: Uint8Array;
  extraAttributes: StunAttribute[];
}

export interface BuildPrivateAllocateRequestOptions {
  transactionId: Uint8Array;
  relayToken: Uint8Array;
  streamSubscriptions: readonly RelayStreamSubscriptionEntry[];
  connIdData: Uint8Array;
  extraAttributes?: readonly StunAttribute[];
  messageIntegrity?: Uint8Array;
  messageIntegrityKey?: Uint8Array;
}

export interface BuildBindingRequestOptions {
  transactionId: Uint8Array;
  extraAttributes?: readonly StunAttribute[];
  messageIntegrity?: Uint8Array;
  messageIntegrityKey?: Uint8Array;
}

export interface BuildBindingSuccessResponseOptions {
  transactionId: Uint8Array;
  extraAttributes?: readonly StunAttribute[];
  messageIntegrity?: Uint8Array;
  messageIntegrityKey?: Uint8Array;
}

export interface BuildRelayPingRequestOptions {
  transactionId: Uint8Array;
  connIdData?: Uint8Array;
  pingTimeoutMs?: number;
  extraAttributes?: readonly StunAttribute[];
  messageIntegrity?: Uint8Array;
  messageIntegrityKey?: Uint8Array;
}

const encodeVarint = (value: number): Uint8Array => {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`invalid varint value: ${value}`);
  }
  const bytes: number[] = [];
  let current = value >>> 0;
  while (current >= 0x80) {
    bytes.push((current & 0x7f) | 0x80);
    current >>>= 7;
  }
  bytes.push(current);
  return new Uint8Array(bytes);
};

const decodeVarint = (
  value: Uint8Array,
  offset: number
): { value: number; nextOffset: number } => {
  let result = 0;
  let shift = 0;
  let cursor = offset;
  while (cursor < value.length) {
    const byte = value[cursor]!;
    result |= (byte & 0x7f) << shift;
    cursor += 1;
    if ((byte & 0x80) === 0) {
      return { value: result >>> 0, nextOffset: cursor };
    }
    shift += 7;
    if (shift > 35) {
      throw new Error("protobuf varint is too long");
    }
  }
  throw new Error("protobuf varint truncated");
};

const buildProtoVarintField = (
  fieldNumber: number,
  value: number
): Uint8Array => concatBytes(encodeVarint((fieldNumber << 3) | 0), encodeVarint(value));

const buildProtoLengthDelimitedField = (
  fieldNumber: number,
  value: Uint8Array
): Uint8Array =>
  concatBytes(
    encodeVarint((fieldNumber << 3) | 2),
    encodeVarint(value.length),
    value
  );

export const parseRelayStreamSubscriptionBlob = (
  value: Uint8Array
): RelayStreamSubscriptionEntry[] => {
  const entries: RelayStreamSubscriptionEntry[] = [];
  let offset = 0;

  while (offset < value.length) {
    const outerTag = decodeVarint(value, offset);
    offset = outerTag.nextOffset;
    const fieldNumber = outerTag.value >>> 3;
    const wireType = outerTag.value & 0x07;
    if (fieldNumber !== 1 || wireType !== 2) {
      throw new Error(
        `unexpected outer stream subscription field ${fieldNumber}/${wireType}`
      );
    }

    const lengthField = decodeVarint(value, offset);
    offset = lengthField.nextOffset;
    const endOffset = offset + lengthField.value;
    if (endOffset > value.length) {
      throw new Error("stream subscription entry exceeds blob length");
    }

    const entry: RelayStreamSubscriptionEntry = {
      participantIndex: 0,
      streamIndex: 0,
      ssrc: 0,
    };

    while (offset < endOffset) {
      const innerTag = decodeVarint(value, offset);
      offset = innerTag.nextOffset;
      const innerField = innerTag.value >>> 3;
      const innerWireType = innerTag.value & 0x07;
      if (innerWireType !== 0) {
        throw new Error(
          `unexpected inner stream subscription field ${innerField}/${innerWireType}`
        );
      }
      const innerValue = decodeVarint(value, offset);
      offset = innerValue.nextOffset;
      switch (innerField) {
        case 1:
          entry.participantIndex = innerValue.value;
          break;
        case 2:
          entry.streamIndex = innerValue.value;
          break;
        case 3:
          entry.ssrc = innerValue.value >>> 0;
          break;
        default:
          throw new Error(`unexpected stream subscription field ${innerField}`);
      }
    }

    if (offset !== endOffset) {
      throw new Error("stream subscription entry parsing did not end cleanly");
    }
    entries.push(entry);
  }

  return entries;
};

export const buildRelayStreamSubscriptionBlob = (
  entries: readonly RelayStreamSubscriptionEntry[]
): Uint8Array => {
  const outerEntries: Uint8Array[] = [];
  for (const entry of entries) {
    const parts: Uint8Array[] = [];
    if (entry.participantIndex !== 0) {
      parts.push(buildProtoVarintField(1, entry.participantIndex));
    }
    if (entry.streamIndex !== 0) {
      parts.push(buildProtoVarintField(2, entry.streamIndex));
    }
    parts.push(buildProtoVarintField(3, entry.ssrc >>> 0));
    outerEntries.push(
      buildProtoLengthDelimitedField(1, concatBytes(...parts))
    );
  }
  return concatBytes(...outerEntries);
};

const padAttributeValue = (value: Uint8Array): Uint8Array => {
  const padLength = (4 - (value.length % 4)) % 4;
  if (padLength === 0) {
    return value;
  }
  return concatBytes(value, new Uint8Array(padLength));
};

export const buildStunAttribute = (
  attrType: number,
  value: Uint8Array
): Uint8Array => {
  const paddedValue = padAttributeValue(value);
  const result = new Uint8Array(4 + paddedValue.length);
  writeUint16BE(result, 0, attrType & 0xffff);
  writeUint16BE(result, 2, value.length & 0xffff);
  result.set(paddedValue, 4);
  return result;
};

export const buildStunPacket = ({
  msgType,
  transactionId,
  attributes,
}: {
  msgType: number;
  transactionId: Uint8Array;
  attributes: readonly StunAttribute[];
}): Uint8Array => {
  if (transactionId.length !== 12) {
    throw new Error(
      `STUN transaction id must be 12 bytes, got ${transactionId.length}`
    );
  }
  const body = concatBytes(
    ...attributes.map((attribute) =>
      buildStunAttribute(attribute.attrType, attribute.value)
    )
  );
  const header = new Uint8Array(20);
  writeUint16BE(header, 0, msgType & 0xffff);
  writeUint16BE(header, 2, body.length & 0xffff);
  writeUint32BE(header, 4, StunMagicCookie);
  header.set(transactionId, 8);
  return concatBytes(header, body);
};

export const computeStunMessageIntegrity = ({
  msgType,
  transactionId,
  attributesBeforeIntegrity,
  key,
}: {
  msgType: number;
  transactionId: Uint8Array;
  attributesBeforeIntegrity: readonly StunAttribute[];
  key: Uint8Array;
}): Uint8Array => {
  const packetForHmac = buildStunPacket({
    msgType,
    transactionId,
    attributes: [
      ...attributesBeforeIntegrity,
      {
        attrType: StunAttrMessageIntegrity,
        value: new Uint8Array(20),
      },
    ],
  }).slice(0, -24);
  return hmacSha1KeyFirst(key, packetForHmac);
};

const findAttribute = (
  attributes: readonly StunAttribute[],
  attrType: number
): Uint8Array => {
  const attribute = attributes.find((entry) => entry.attrType === attrType);
  if (!attribute) {
    throw new Error(`missing STUN attribute 0x${attrType.toString(16)}`);
  }
  return attribute.value;
};

export const parsePrivateAllocateRequest = (
  packetBytes: Uint8Array
): ParsedPrivateAllocateRequest => {
  const packet = parseStun(packetBytes);
  if (packet.msgType !== StunTypePrivateAllocateRequest) {
    throw new Error(
      `expected private allocate request 0x${StunTypePrivateAllocateRequest.toString(16)}, got 0x${packet.msgType.toString(16)}`
    );
  }

  const relayToken = findAttribute(packet.attributes, StunAttrRelayToken);
  const streamSubscriptionRaw = findAttribute(
    packet.attributes,
    StunAttrStreamSubscription
  );
  const connIdData = findAttribute(packet.attributes, StunAttrConnectionId);
  const messageIntegrity = findAttribute(
    packet.attributes,
    StunAttrMessageIntegrity
  );

  return {
    packet,
    relayToken,
    streamSubscriptionRaw,
    streamSubscriptions: parseRelayStreamSubscriptionBlob(
      streamSubscriptionRaw
    ),
    connIdData,
    connId: connIdData.length === 8 ? readUint64BE(connIdData, 0) : undefined,
    messageIntegrity,
    extraAttributes: packet.attributes.filter(
      (attribute) =>
        ![
          StunAttrRelayToken,
          StunAttrStreamSubscription,
          StunAttrConnectionId,
          StunAttrMessageIntegrity,
        ].includes(attribute.attrType)
    ),
  };
};

export const buildPrivateAllocateRequest = ({
  transactionId,
  relayToken,
  streamSubscriptions,
  connIdData,
  extraAttributes = [],
  messageIntegrity,
  messageIntegrityKey,
}: BuildPrivateAllocateRequestOptions): Uint8Array => {
  const streamSubscriptionValue =
    streamSubscriptions.length > 0
      ? buildRelayStreamSubscriptionBlob(streamSubscriptions)
      : null;
  const attributesBeforeIntegrity: StunAttribute[] = [
    {
      attrType: StunAttrRelayToken,
      value: relayToken,
    },
    ...(streamSubscriptionValue
      ? [
          {
            attrType: StunAttrStreamSubscription,
            value: streamSubscriptionValue,
          } satisfies StunAttribute,
        ]
      : []),
    {
      attrType: StunAttrConnectionId,
      value: connIdData,
    },
    ...extraAttributes,
  ];

  const resolvedMessageIntegrity =
    messageIntegrityKey !== undefined
      ? computeStunMessageIntegrity({
          msgType: StunTypePrivateAllocateRequest,
          transactionId,
          attributesBeforeIntegrity,
          key: messageIntegrityKey,
        })
      : messageIntegrity;

  const attributes =
    resolvedMessageIntegrity !== undefined
      ? [
          ...attributesBeforeIntegrity,
          {
            attrType: StunAttrMessageIntegrity,
            value: resolvedMessageIntegrity,
          },
        ]
      : attributesBeforeIntegrity;

  return buildStunPacket({
    msgType: StunTypePrivateAllocateRequest,
    transactionId,
    attributes,
  });
};

export const buildBindingRequest = ({
  transactionId,
  extraAttributes = [],
  messageIntegrity,
  messageIntegrityKey,
}: BuildBindingRequestOptions): Uint8Array => {
  const attributesBeforeIntegrity = [...extraAttributes];
  const resolvedMessageIntegrity =
    messageIntegrityKey !== undefined
      ? computeStunMessageIntegrity({
          msgType: StunTypeBindingRequest,
          transactionId,
          attributesBeforeIntegrity,
          key: messageIntegrityKey,
        })
      : messageIntegrity;

  const attributes =
    resolvedMessageIntegrity !== undefined
      ? [
          ...attributesBeforeIntegrity,
          {
            attrType: StunAttrMessageIntegrity,
            value: resolvedMessageIntegrity,
          },
        ]
      : attributesBeforeIntegrity;

  return buildStunPacket({
    msgType: StunTypeBindingRequest,
    transactionId,
    attributes,
  });
};

export const buildBindingSuccessResponse = ({
  transactionId,
  extraAttributes = [],
  messageIntegrity,
  messageIntegrityKey,
}: BuildBindingSuccessResponseOptions): Uint8Array => {
  const attributesBeforeIntegrity = [...extraAttributes];
  const resolvedMessageIntegrity =
    messageIntegrityKey !== undefined
      ? computeStunMessageIntegrity({
          msgType: 0x0101,
          transactionId,
          attributesBeforeIntegrity,
          key: messageIntegrityKey,
        })
      : messageIntegrity;

  const attributes =
    resolvedMessageIntegrity !== undefined
      ? [
          ...attributesBeforeIntegrity,
          {
            attrType: StunAttrMessageIntegrity,
            value: resolvedMessageIntegrity,
          },
        ]
      : attributesBeforeIntegrity;

  return buildStunPacket({
    msgType: 0x0101,
    transactionId,
    attributes,
  });
};

export const buildPrivateKeepaliveIndication = (
  transactionId: Uint8Array
): Uint8Array =>
  buildStunPacket({
    msgType: StunTypePrivateKeepaliveIndication,
    transactionId,
    attributes: [],
  });

export const buildRelayPingRequest = ({
  transactionId,
  connIdData,
  pingTimeoutMs = 0x01f4,
  extraAttributes = [],
  messageIntegrity,
  messageIntegrityKey,
}: BuildRelayPingRequestOptions): Uint8Array => {
  const timeoutValue = new Uint8Array(2);
  writeUint16BE(timeoutValue, 0, pingTimeoutMs & 0xffff);

  const attributesBeforeIntegrity: StunAttribute[] = [
    {
      attrType: StunAttrRelayPingTimeout,
      value: timeoutValue,
    },
    ...(connIdData && connIdData.length > 0
      ? [
          {
            attrType: StunAttrConnectionId,
            value: connIdData,
          } satisfies StunAttribute,
        ]
      : []),
    ...extraAttributes,
  ];

  const resolvedMessageIntegrity =
    messageIntegrityKey !== undefined
      ? computeStunMessageIntegrity({
          msgType: StunTypePrivatePingRequest,
          transactionId,
          attributesBeforeIntegrity,
          key: messageIntegrityKey,
        })
      : messageIntegrity;

  const attributes =
    resolvedMessageIntegrity !== undefined
      ? [
          ...attributesBeforeIntegrity,
          {
            attrType: StunAttrMessageIntegrity,
            value: resolvedMessageIntegrity,
          },
        ]
      : attributesBeforeIntegrity;

  return buildStunPacket({
    msgType: StunTypePrivatePingRequest,
    transactionId,
    attributes,
  });
};
