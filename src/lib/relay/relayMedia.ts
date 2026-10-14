/**
 * ============================================================================
 * STACK LAYER 6 — Media orchestration (slim bridge)
 * ============================================================================
 *
 * A minimal SRTP bridge (uplink protect + downlink unprotect) used as a fallback
 * when the full MediaPipeline is not active.
 *
 * Why: some flows just need cleartext<->SRTP conversion without the full encode/
 * pace machinery. Hands off: wraps srtp (layer 3) for both directions.
 */
/**
 * Slim SRTP bridge: converts between cleartext RTP/RTCP and SRTP-protected
 * wire packets in both directions using a pair of SRTP contexts (uplink for
 * outgoing, downlink for incoming). Used as a fallback when the full
 * MediaPipeline is not active.
 */

import { parseDatagram, type DatagramInfo } from "../protocol/protocol";
import { SrtpContext } from "../crypto/srtp";

export interface RelayMediaBridgeResult {
  encrypted: Uint8Array;
  datagram: DatagramInfo;
  clear?: Uint8Array;
  clearDatagram?: DatagramInfo;
  rtcpIndex?: number;
}

export class RelayMediaBridge {
  #uplink: SrtpContext;
  #downlink: SrtpContext;
  #roc = 0;
  #rtcpSendIndex = 0;

  constructor({ uplink, downlink }: { uplink: SrtpContext; downlink?: SrtpContext }) {
    this.#uplink = uplink;
    this.#downlink = downlink ?? uplink;
  }

  protectOutgoingRtp(packet: Uint8Array): Uint8Array {
    return this.#uplink.protectRtp(packet, this.#roc);
  }

  protectOutgoingRtcp(packet: Uint8Array): { packet: Uint8Array; index: number } {
    const index = this.#rtcpSendIndex;
    this.#rtcpSendIndex += 1;
    return { packet: this.#uplink.protectRtcp(packet, index), index };
  }

  handleIncomingDatagram(encrypted: Uint8Array, sourceHost = "", sourcePort = 0): RelayMediaBridgeResult {
    const datagram = parseDatagram(encrypted, sourceHost, sourcePort);
    if (datagram.kind === "rtp") {
      const clear = this.#downlink.unprotectRtp(encrypted, this.#roc);
      return { encrypted, datagram, clear, clearDatagram: parseDatagram(clear, sourceHost, sourcePort) };
    }
    if (datagram.kind === "rtcp") {
      const unprotected = this.#downlink.unprotectRtcp(encrypted);
      return {
        encrypted, datagram,
        clear: unprotected.packet,
        clearDatagram: parseDatagram(unprotected.packet, sourceHost, sourcePort),
        rtcpIndex: unprotected.index,
      };
    }
    return { encrypted, datagram };
  }
}
