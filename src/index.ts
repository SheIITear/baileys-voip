/**
 * Re-exports the whole stack: the WhatsAppVoipNode engine plus every layer's
 * parsers/builders (protocol, relay, srtp/srtp1to1, warp, sframe, rtpEngine,
 * xmpp), the MLow encoder (mlowWasmRtp, vendored libopus-wasm) and the ffmpeg
 * RTP receiver (ffmpegRtp), the media pipeline, the crypto/byte utilities, the
 * type contracts, and the diagnostics / trace / TUI helpers. ESM-only, no
 * browser polyfills.
 */

export type {
  VoipCallbacks,
  VoipConfig,
  VoipOptions,
  AudioConfig,
  VideoConfig,
  VideoFrame,
  StartCallOptions,
  SignalingMessage,
  CallInfo,
} from "./lib/core/types";

export { WhatsAppVoipNode, WhatsAppVoipNode as WhatsAppVoipWasm } from "./lib/engine/node";
export * from "./lib/core/crypto";
export * from "./lib/core/bytes";
export * from "./lib/protocol/protocol";
export * from "./lib/protocol/relay";
export * from "./lib/relay/relayTransport";
export * from "./lib/protocol/xmpp";
export * from "./lib/crypto/srtp";
export * from "./lib/crypto/warp";
export * from "./lib/crypto/sframe";
export * from "./lib/media/mlowWasmRtp";
export * from "./lib/relay/relayMedia";
export * from "./lib/relay/relayController";
export * from "./lib/media/mediaPipeline";
export * from "./lib/media/rtpEngine";
export * from "./lib/app/trace";
export * from "./lib/app/diag";
export * from "./lib/app/callTui";
export * from "./lib/app/whatsapp-signaling";
export {
  deriveE2EKeys as deriveE2ESrtpKeys,
  deriveE2EKeysFromRawE2E as deriveE2ESrtpKeysFromRawE2E,
  protectRtp1to1,
  unprotectRtp1to1,
  cryptSrtpPayload as cryptSrtpPayload1to1,
  type E2ESrtpKeys,
} from "./lib/crypto/srtp1to1";
