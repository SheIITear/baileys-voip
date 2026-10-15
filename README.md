# baileys-voip

A pure Node.js / TypeScript reimplementation of WhatsApp's VoIP calling engine —
places real 1:1 and group calls through WhatsApp's relay infrastructure:
Signal-encrypted call signaling over XMPP, MLow audio media with SRTP, and
STUN-based relay allocation. No browser, no bundled WASM runtime, no Docker.

> Research / interoperability project — use responsibly and at your own risk.

[![Example](https://img.youtube.com/vi/hbD-OMV06mo/0.jpg)](https://www.youtube.com/watch?v=hbD-OMV06mo)

## Requirements

- Node.js 20.9+
- `ffmpeg` on `PATH` (PCM decode for the audio source, and the RTP receive path)
- A Baileys multi-file auth directory (your own account; **never commit it**)
- `@roamhq/wrtc` for the WebRTC DataChannel relay transport (optional; raw UDP
  works for testing)

## Quick start

```bash
npm install
npm run build            # tsc -> dist/
npm run typecheck        # optional: tsc --noEmit
npm run test:call -- <target> [authDir] [audioFile]
```

| Argument   | Default                          | Description |
|------------|----------------------------------|-------------|
| `target`   | (required)                       | Phone number to call (digits only) |
| `authDir`  | `./auth`                         | Baileys multi-file auth state directory |
| `audioFile`| `lavfi:sine=frequency=440`       | Audio source for ffmpeg: file path or `lavfi:` spec |

`--verbose` / `-v` replaces the live terminal UI with raw engine logs.

## Usage

The library exports the engine and every protocol layer. Minimal caller:

```ts
import { WhatsAppVoipNode } from "baileys-voip";
import { randomBytes } from "node:crypto";

const voip = new WhatsAppVoipNode({
  audioSource: "song.mp3",                 // any ffmpeg-decodable file, or a lavfi: spec
  callbacks: {
    onLog: (level, msg) => console.log(msg),
    onCallEvent: (type, data) => { /* state changes, relay updates */ },
    onAudioPlaybackData: (samples) => { /* decoded PCM from the peer */ },
  },
});
await voip.initialize();
voip.initVoipStack(selfPnJid, selfPnBareJid, selfLidJid);

// 1:1 E2E keying — call BEFORE the offer ack arrives
voip.setE2ECallKey(randomBytes(32), selfLid, peerLid, peerDeviceLids);

voip.startCall({ callId: randomBytes(16).toString("hex"), peerJid: peerLid, peerPn, isVideo: false });

// The engine emits the offer via onSignalingXmpp (JSON or XML). You wrap it in a
// <call> stanza, encrypt the call key per device with Signal, and send it through
// Baileys. Inbound <call> stanzas go back in via:
voip.handleSignalingMessage({ payload: xmlString });
```

Relay transport — the engine needs a `send` callback. Two options:

```ts
// A) Raw UDP (testing)
const socket = dgram.createSocket("udp4");
voip.setRelaySendCallback((packet, ip, port) => socket.send(packet, port, ip));
socket.on("message", (msg, rinfo) => voip.feedRelayDatagram(new Uint8Array(msg), rinfo.address, rinfo.port));

// B) WebRTC DataChannel (production, via @roamhq/wrtc)
import { RelayRtcTransport } from "baileys-voip";
const relayTransport = new RelayRtcTransport({
  onTransportMessage: (data, ip, port) => voip.feedRelayDatagram(new Uint8Array(data), ip, port),
});
voip.setRelaySendCallback((packet, ip, port) => relayTransport.send(Buffer.from(packet), ip, port));
voip.callbacks.onCallEvent = (type, data) => {
  if (type === 156) relayTransport.updateRelayList(JSON.parse(data));  // relay-list update
};
```

Working reference callers live in `src/examples/`:

| Example | What it does |
|---------|--------------|
| `baileys-real-call.mts` | Full lifecycle: own Baileys auth ↔ engine bridge, Signal call-key encryption, offer/preaccept/accept/relaylatency/mute_v2 handling, media + live TUI |
| `bot-integration.mts` | **Minimal drop-in for your existing bot**: `attachCalling(sock)` → `placeCall(number)` / `endCall(callId)` — engine + relay bridge + inbound stanza hook, ~130 lines |
| `test-call-mlow.mts` | Thin wrapper that pins the MLow encoder and takes `<target> [authDir] [audioFile]` |

## Library structure

```
src/
├── index.ts                    # Public API exports (engine + every layer)
├── lib/
│   ├── engine/                 # Top-level call engine
│   │   ├── node.ts             #   WhatsAppVoipNode — lifecycle, signaling, relay orchestration
│   │   ├── helpers.ts          #   JID parsing, SSRC plans, endpoint decoding
│   │   ├── relay-setup.ts      #   Transport application, controller spawning, pipeline bootstrap
│   │   └── e2e.ts              #   E2E key derivation & downlink relocking
│   ├── media/                  # Audio pipeline
│   │   ├── mediaPipeline.ts    #   Encoder → pacer → SRTP → relay (both directions)
│   │   ├── mlowWasmRtp.ts      #   MLow encoder via vendored libopus-wasm (useSmpl, CTL 4050)
│   │   ├── ffmpegRtp.ts        #   ffmpeg Opus RTP receiver (decode to PCM)
│   │   └── rtpEngine.ts        #   RTP send/receive with ROC tracking, WARP framing
│   ├── crypto/                 # Media encryption
│   │   ├── srtp.ts             #   SRTP (AES-128-CTR + HMAC-SHA1), HBH key derivation
│   │   ├── srtp1to1.ts         #   1:1 E2E SRTP (HKDF + AES-CM PRF)
│   │   ├── sframe.ts           #   SFrame per-frame AES-GCM for E2E group calls
│   │   └── warp.ts             #   WARP extension framing (0xDEBE), MI tags
│   ├── protocol/               # Wire protocol parsers & builders
│   │   ├── protocol.ts         #   Packet classification (STUN/DTLS/RTP/RTCP), parsers, builders
│   │   ├── relay.ts            #   STUN relay messages (allocate, bind, keepalive)
│   │   └── xmpp.ts             #   XMPP call signaling parser (offer/preaccept/accept/ack/…)
│   ├── relay/                  # Relay transport & control
│   │   ├── relayController.ts  #   Per-endpoint state machine (creating → allocated → bound → ready)
│   │   ├── relayTransport.ts   #   Transport stanza normalization
│   │   ├── relayMedia.ts       #   Slim SRTP bridge (uplink protect + downlink unprotect)
│   │   └── RelayRtcTransport.mts  # WebRTC DataChannel transport
│   ├── core/                   # Shared primitives
│   │   ├── crypto.ts           #   HKDF, HMAC, SHA-256, SSRC derivation
│   │   ├── bytes.ts            #   Byte encoding/decoding utilities
│   │   └── types.ts            #   TypeScript interfaces & enums
│   └── app/                    # Bridge & diagnostics
│       ├── diag.ts             #   Human-readable per-packet diagnostics
│       ├── trace.ts            #   JSONL tracer
│       ├── callTui.ts          #   Live terminal UI
│       └── whatsapp-signaling.ts  # Baileys/XMPP bridge: offer + relaylatency builders, Signal call-key encryption
├── examples/                   # Reference callers (see table above)
└── vendor/
    └── libopus-wasm/           # WASM libopus encoder bindings with WhatsApp's SMPL/MLow extension
```

Outbound audio flows: `ffmpeg decode → MLow encoder (vendor/libopus-wasm) → pacer → RTP/WARP framing → SRTP → relay`. Inbound is the reverse; decoded PCM arrives via `onAudioPlaybackData`. The full layer-by-layer protocol reference (stanza structures, STUN message layout, key derivation formulas, WARP framing, encoder env vars) is in [stack.md](stack.md).

## Diagnostics

| Env Variable | Purpose |
|-------------|---------|
| `CALL_DIAG=0` | Disable per-packet diagnostics |
| `CALL_DIAG_VERBOSE=1` | Log every packet |
| `CALL_DUMP_NODE_TRACE=0` | Disable JSONL tracer |
| `CALL_VERBOSE=1` | Disable TUI, stream raw logs |
| `CALL_REPLAY_OPUS_PATH` | Replay a captured frame stream instead of encoding live |
| `CALL_DUMP_OPUS_FRAMES_PATH` | Dump bare Opus/MLow frames to JSONL |
| `CALL_RELAY_PORT_MODE` | `original` or `web` port mapping |
| `CALL_DISABLE_IPV6` | Skip IPv6 relay endpoints |

## License

UNLICENSED (research use). The vendored libopus fork (SMPL/MLow extension)
carries its own BSD-style license.
