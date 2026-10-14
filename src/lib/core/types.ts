/**
 * Type definitions for the WhatsApp VoIP engine (mirrors WAWebVoipStackInterface).
 *
 * Interfaces for engine configuration (VoipConfig), call setup (StartCallOptions,
 * SignalingMessage), callback contracts (VoipCallbacks), and call state enums
 * (CallEventType, CallState, CallEndReason, NetworkMedium). These types define
 * the surface area between the engine and consumer-controlled signaling/transport.
 */

import type { RelayStreamSubscriptionEntry } from "../protocol/relay";

// CONFIGURATION

export interface AudioConfig {
  sampleRate: number;
  channels: number;
  bitsPerSample: number;
  framesPerChunk: number;
}

export interface VideoConfig {
  cameraId?: string;
  width: number;
  height: number;
  maxFps: number;
}

export interface VideoFrame {
  userJid: string;
  frameBuffer: Uint8Array;
  width: number;
  height: number;
  orientation: number;
  format: number;
  timestamp: number;
  isKeyFrame: boolean;
}

// CALLBACKS - Called by the engine

export interface VoipCallbacks {
  // SIGNALING
  /**
   * Called when the engine needs to send signaling XMPP.
   * Consumer should send this via the Baileys socket.
   */
  onSignalingXmpp?: (peerJid: string, callId: string, xmlPayload: Uint8Array) => void | Promise<void>;
  
  // CALL EVENTS
  /**
   * Called when a call event occurs.
   * eventType maps to WhatsApp's CallEvent enum.
   * 
   * Notable events:
   * - 1: CallStateChanged
   * - 3: RingingStarted
   * - 4: RingingEnded
   * - 100: CallEnded
   * - 156: RelayListUpdate (relay endpoint list)
   */
  onCallEvent?: (eventType: number, eventData?: string) => void;
  
  /**
   * Called when the VoIP stack is ready.
   */
  onVoipReady?: () => void;
  
  // NETWORK
  /**
   * Called when the engine needs to send data to a relay.
   */
  sendDataToRelay?: (data: Uint8Array, ip: string, port: number) => number;

  /**
   * Publishes P2P transport signaling in WA Web stack format.
   * The bridge decides the final XMPP; the caller provides credentials/candidates.
   */
  sendWebP2PTransport?: (
    callId: string,
    ufrag: string,
    pwd: string,
    algo: string,
    fingerprint: string,
    candidates: Array<{ ip: string; port: number; priority: string }>
  ) => void | Promise<void>;
  
  // LOGGING
  /**
   * Called for engine logs.
   * level: 'error' | 'warn' | 'log' | 'debug'
   */
  onLog?: (level: string, message: string) => void;
  
  // AUDIO CAPTURE
  /**
   * Called when the audio capture driver is initialized.
   * Contains audio config (sample rate, channels, etc.)
   */
  onAudioCaptureInit?: (config: AudioConfig) => void;
  
  /**
   * Called when audio capture should start.
   * Consumer should begin providing audio data via sendAudioData().
   */
  onAudioCaptureStart?: () => void;
  
  /**
   * Called when audio capture should stop.
   */
  onAudioCaptureStop?: () => void;
  
  // AUDIO PLAYBACK
  /**
   * Called when the audio playback driver is initialized.
   */
  onAudioPlaybackInit?: (config: AudioConfig) => void;
  
  /**
   * Called when audio playback should start.
   */
  onAudioPlaybackStart?: () => void;
  
  /**
   * Called when audio playback should stop.
   */
  onAudioPlaybackStop?: () => void;
  
  /**
   * Called when audio data is available for playback.
   * Data is a normalized Float32Array (-1.0 to 1.0).
   */
  onAudioPlaybackData?: (audioData: Float32Array) => void;
  
  // VIDEO CAPTURE
  /**
   * Called when video capture should start.
   */
  onVideoCaptureStart?: (config: VideoConfig) => void;
  
  /**
   * Called when video capture should stop.
   */
  onVideoCaptureStop?: () => void;
  
  /**
   * Called when a video frame from the peer is available for rendering.
   */
  onVideoFrame?: (frame: VideoFrame) => void;
  
  // DESKTOP SHARING
  /**
   * Called when screen sharing should start.
   */
  onDesktopCaptureStart?: (config: VideoConfig) => void;
  
  /**
   * Called when screen sharing should stop.
   */
  onDesktopCaptureStop?: () => void;
  
  // CRYPTO
  /**
   * HKDF - Extract and Expand.
   * Used for key derivation.
   */
  cryptoHkdf?: (key: Uint8Array, salt: Uint8Array | null, info: Uint8Array, length: number) => Uint8Array;
  
  /**
   * HMAC-SHA256.
   * Used for signatures.
   */
  hmacSha256?: (data: Uint8Array, key: Uint8Array) => Uint8Array;
  
  // CONTACTS
  /**
   * Checks if a participant is a known contact.
   * Used for privacy checks.
   */
  isParticipantKnownContact?: (jid: string) => boolean;
}

// CONFIGURATION OPTIONS

export interface VoipOptions {
  /** Heartbeat interval in seconds (default: 30) */
  heartbeatInterval?: number;
  
  /** Lobby timeout in minutes (default: 5) */
  lobbyTimeout?: number;
  
  /** Max participants for screen sharing (default: 32) */
  maxParticipantsScreenShare?: number;
  
  /** Max group size for long ringtone (default: 32) */
  maxGroupSizeLongRingtone?: number;

  /** Native WASM log level */
  logLevel?: number;
  
  /** Enable passthrough video decoder (default: false) */
  enablePassthroughVideoDecoder?: boolean;
}

export interface VoipConfig {
  /** Callbacks the engine will invoke */
  callbacks?: VoipCallbacks;
  
  /** Configuration options */
  options?: VoipOptions;
  
  /** Enable/disable engine logs and callbacks (default: true) */
  enableLogs?: boolean;

  /**
   * When `true`, `startCall()` emits a real WhatsApp XMPP `<offer>` node
   * (rendered via `renderXmlNode`) instead of the legacy JSON envelope.
   * The legacy JSON path remains the default so existing parity bridges
   * keep working. New consumers that want to talk to the relay end-to-end
   * without an external bridge should opt in.
   */
  useXmppOffer?: boolean;

  /**
   * Optional source for the local audio capture pipeline. Anything ffmpeg
   * accepts is fine: a file path, an `lavfi:...` URL, or a device URI.
   */
  audioSource?: string;

  /**
   * Optional override for the upstream audio SSRC. When omitted the engine
   * picks a fresh random 32-bit value at offer time.
   */
  senderSsrc?: number;

  /**
   * Optional override for the relay control retry / keepalive cadence.
   */
  relayControl?: {
    keepaliveIntervalMs?: number;
    pingIntervalMs?: number;
    allocateRetryMs?: number;
  };

  /**
   * Stream subscription plan used for the private allocate request. When
   * omitted the engine generates a single-audio plan at offer time.
   */
  streamSubscriptions?: RelayStreamSubscriptionEntry[];

  /**
   * Skip IPv6 relay endpoints when spawning controllers. Default: `true`,
   * since most consumers bind a `udp4`-only `dgram.Socket` and would hit
   * EINVAL on every IPv6 send. Set to `false` if you've wired up a `udp6`
   * (or dual-stack) send callback.
   */
  disableIpv6?: boolean;
}

// CALLS - Options for starting calls

export interface StartCallOptions {
  /** Recipient LID */
  peerJid: string;
  
  /** Peer list (for group calls) */
  peerList?: string[];
  
  /** Unique call ID (generated by caller) */
  callId: string;
  
  /** true for video call, false for audio */
  isVideo: boolean;
  
  /** PEER phone number JID */
  peerPn: string;

  /** true when the call was initiated in LID mode */
  isLidCall?: boolean;

  /** true when the call came from the dialer */
  isFromDialer?: boolean;
  
  /** true for audio-only (even in a video call) */
  isAudioOnly?: boolean;
  
  /** true for group calls */
  isGroupCall?: boolean;
  
  /** Extra data (TC Token, etc.) */
  extraData?: Uint8Array;
}

// SIGNALING - Signaling messages

export interface SignalingMessage {
  /** WAP node payload in base64 */
  payload: string;
  
  /** Peer JID */
  peerJid?: string;
  
  /** Sender JID */
  senderJid?: string;
  
  /** Call creator JID */
  callCreator?: string;
  
  /** Sequence number */
  seqNum?: string;
  
  /** ACK sequence number */
  ackSeqNum?: string;
  
  /** Message type (offer, answer, etc.) */
  msgType?: string;

  /** ACK XMPP/voip error field */
  ackError?: string;
  
  /** Timestamp */
  timestamp?: string;
  
  /** Whether this is a retransmission */
  isRetry?: boolean;
  
  /** Extra data (string) */
  extra?: string;
  
  /** Extra data in bytes (TC Token) */
  extraData?: Uint8Array;
}

// CALL INFO

export interface CallInfo {
  /** AEC mode */
  aec_mode?: number;
  
  /** Audio duration in seconds */
  audio_duration?: number;
  
  /** Bytes received */
  bytes_received?: number;
  
  /** Bytes sent */
  bytes_sent?: number;
  
  /** Active call duration */
  call_active_duration?: number;
  
  /** Total call duration */
  call_duration?: number;
  
  /** Call end reason */
  call_end_reason?: number;
  
  /** Call ID */
  call_id?: string;
  
  /** Whether this is a video call */
  is_video_call?: boolean;
  
  /** Peer JID */
  peer_jid?: string;
  
  /** Additional fields */
  [key: string]: any;
}

// ENUMS — Extracted from WAWebVoipWaCallEnums

/**
 * Call event types.
 * Extracted from WAWebVoipWaCallEnums.CallEvent
 */
export enum CallEventType {
  None = 0,
  CallOfferSent = 1,
  CallOfferReceived = 2,
  CallOfferAcked = 3,
  CallOfferNacked = 4,
  CallOfferReceiptReceived = 5,
  CallAcceptFailed = 6,
  CallAcceptSent = 7,
  CallAcceptReceived = 8,
  CallPreacceptReceived = 9,
  CallTerminateReceived = 10,
  CallRejectReceived = 11,
  CallOfferResend = 12,
  AudioStreamStarted = 13,
  P2PNegotiationSuccess = 14,
  RelayCreateSuccess = 15,
  CallStateChanged = 16,
  P2PNegotiationFailed = 17,
  MediaStreamError = 18,
  AudioInitError = 19,
  NoSamplingRatesForAudioRecord = 20,
  SendOfferFailed = 21,
  HandleOfferFailed = 22,
  SendAcceptFailed = 23,
  HandlePreAcceptFailed = 24,
  HandleAcceptFailed = 25,
  WillCreateSoundPort = 26,
  SoundPortCreateFailed = 27,
  TransportCandSendFailed = 28,
  P2PTransportCreateFailed = 29,
  P2PTransportMediaCreateFailed = 30,
  P2PTransportStartFailed = 31,
  P2PTransportRestartSuccess = 32,
  MissingRelayInfo = 33,
  ErrorGatheringHostCandidates = 34,
  MediaStreamStartError = 35,
  RelayLatencySendFailed = 36,
  RelayElectionSendFailed = 37,
  CallEnding = 38,
  CallCaptureBufferFilled = 39,
  CallCaptureEnded = 40,
  RxTimeout = 41,
  TxTimeout = 42,
  RxTrafficStarted = 43,
  RxTrafficStopped = 44,
  RTCPPacketReceived = 45,
  RTCPByeReceived = 46,
  RelayBindsFailed = 47,
  SoundPortCreated = 48,
  AudioDriverRestart = 49,
  Echo = 50,
  SelfVideoStateChanged = 51,
  PeerVideoStateChanged = 52,
  VideoPortCreated = 53,
  VideoPortCreateFailed = 54,
  VideoDecodeStarted = 55,
  VideoRenderStarted = 56,
  VideoCaptureStarted = 57,
  VideoPreviewFailed = 58,
  VideoPreviewReady = 59,
  VideoPreviewShouldMinimize = 60,
  VideoStreamCreateError = 61,
  VideoRenderFormatChanged = 62,
  VideoCodecMismatch = 63,
  VideoDecodePaused = 64,
  VideoDecodeResumed = 65,
  VideoEncodeFatalError = 66,
  VideoDecodeFatalError = 67,
  BatteryLevelLow = 68,
  PeerBatteryLevelLow = 69,
  GroupInfoChanged = 70,
  FieldstatsReady = 71,
  CallWaitingStateChanged = 72,
  MuteStateChanged = 73,
  InterruptionStateChanged = 74,
  RxTrafficStateForPeerChanged = 75,
  HandleAcceptReceiptFailed = 76,
  GroupParticipantLeft = 77,
  AudioRouteChangeRequest = 78,
  HandleAcceptAckFailed = 79,
  CallMissed = 80,
  WeakWiFiSwitchedToCellular = 81,
  CallAutoConnect = 82,
  RejectedDecryptionFailure = 83,
  PeerDeviceOrientationChanged = 84,
  HandleOfferAckFailed = 85,
  PendingCallAutoRejected = 86,
  FDLeakDetected = 87,
  RestartCamera = 88,
  AudioTestReplayFinished = 89,
  SyncDevices = 90,
  VideoCodecStateChanged = 91,
  CallFatal = 92,
  UpdateJoinableCallLog = 93,
  LobbyNacked = 94,
  PlayCallTone = 95,
  SendJoinableClientPollCriticalEvent = 96,
  SendLinkedGroupCallDowngradedCriticalEvent = 97,
  UpdateVoipSettings = 98,
  VoipErrDetectorEvent = 99,
  SpeakerStatusChanged = 100, // Audio levels (NOT CallEnded!)
  LonelyStateTimeout = 101,
  MutedByOthers = 102,
  LinkCreateAcked = 103,
  LinkCreateNacked = 104,
  HeartbeatNacked = 105,
  CallLinkStateChanged = 106,
  LobbyTimeout = 107,
  MuteRequestFailed = 108,
  LinkQueryNacked = 109,
  LinkJoinNacked = 110,
  CallGridRankingChanged = 111,
  GroupCallBufferHandleMessages = 112,
  RemoveUserNacked = 113,
  VideoRenderingStateChanged = 114,
  UserRemoved = 115,
  ScreenShare = 116,
  NetHealthStatusChanged = 117,
  ReminderSetAcked = 118,
  HighDataUsageDetected = 119,
  LidCallerDisplayInfo = 120,
  EagerCallDismiss = 121,
  OfferPeekTimeout = 122,
  NetHealthStatusChangedV2 = 123,
  AutoVideoPauseStateChanged = 124,
  BCallCreated = 125,
  BCallCreateFailed = 126,
  BCallAudienceUpdated = 127,
  CallSummaryReceived = 128,
  BCallJoinFailed = 129,
  BCallEndFailed = 130,
  BCallJoined = 131,
  BCallLeaveFailed = 132,
  ScreenContentType = 133,
  BCallEnded = 134,
  BCallStartNotify = 135,
  LinkEditAcked = 136,
  LinkEditNacked = 137,
  Update1to1CallLog = 138,
  CallLinkSelfStateChanged = 139,
  DataChannelReady = 140,
  AudioTxStarted = 141,
  HandleGroupCallReminder = 142,
  VoiceChatWaveReceived = 143,
  DataChannelConnectionTimeout = 144,
  ReactionStateChanged = 145,
  VideoStateChanged = 146,
  PeerVideoPermissionChanged = 147,
  RaiseHandStateChanged = 148,
  RelayListUpdate = 156,
  Max = 157,
}

/**
 * Call states.
 * Extracted from WAWebVoipWaCallEnums.CallState
 */
export enum CallState {
  None = 0,
  Calling = 1,
  PreacceptReceived = 2,
  ReceivedCall = 3,
  AcceptSent = 4,
  AcceptReceived = 5,
  CallActive = 6,
  CallActiveElseWhere = 7,
  ReceivedCallWithoutOffer = 8,
  Rejoining = 9,
  Link = 10,
  ConnectedLonely = 11,
  PreCalling = 12,
  CallStateEnding = 13,
  CallBCallStarting = 14,
}

/**
 * Call end reasons.
 */
export enum CallEndReason {
  Unknown = 0,
  Normal = 1,
  Busy = 2,
  Declined = 3,
  Timeout = 4,
  Unavailable = 5,
  Cancelled = 6,
  Failed = 7,
}

/**
 * Network medium types.
 * Based on WAWebWamEnumCallNetworkMedium
 */
export enum NetworkMedium {
  CELLULAR = 1,
  WIFI = 2,
  NONE = 3,
}
