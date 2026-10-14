# WhatsApp VoIP Stack — Pure Node.js Implementation

A complete, protocol-compatible reimplementation of WhatsApp's VoIP engine
(`wa_voip_wasm`) in pure Node.js (TypeScript). Drives real 1:1 and group calls
through WhatsApp's relay infrastructure, Signal-encrypted call signaling, SRTP
media encryption with WARP framing, and STUN-based relay allocation.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    WhatsAppVoipNode (engine)                    │
│  ┌──────────┐  ┌────────────┐  ┌──────────────┐  ┌──────────┐  │
│  │ Signaling│  │  Relay     │  │   Media      │  │  Crypto  │  │
│  │ (XMPP)   │  │Controller×N│  │  Pipeline    │  │  (SRTP)  │  │
│  └────┬─────┘  └─────┬──────┘  └──────┬───────┘  └────┬─────┘  │
│       │              │                │               │         │
│   parseStanza    STUN lifecycle   MediaPipeline   SrtpContext   │
│   buildOffer      allocate/bind    mlowWasmRtp/   E2E / HBH     │
│   handleAccept    keepalive/ping   ffmpeg decode   key deriv.   │
│       │              │                │               │         │
│  ─ ─ ─│─ ─ ─ ─ ─ ─ ─ │ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─  ─ │ ─ ─ ─ ─ │
│  Consumer bridge: Baileys, dgram.Socket, RelayRtcTransport      │
└─────────────────────────────────────────────────────────────────┘
```

### Stack Protocol (layer order)

Outbound audio travels top-to-bottom; inbound travels bottom-to-top. Every
source file documents which layer it implements and how its bytes hand off to
the next layer.

```
 Layer                     Module(s)                       Bytes on the wire
 ───────────────────────────────────────────────────────────────────────────
 8  Application / TUI      examples/*, callTui.ts          (console only)
 7  Call signaling         node, xmpp, relayTransport      <call><offer/accept…>
 6  Media orchestration    mediaPipeline                   (frame scheduling)
 5  Audio codec            mlowWasmRtp                     MLow payload
 4  RTP framing            rtpEngine, warp                 RTP hdr + WARP ext
 3  Media crypto           srtp, srtp1to1, sframe          AES-CTR ciphertext
                                                           + WARP MI tag
 2  Relay control          relayController, relay          STUN allocate/bind
 1  Relay transport        RelayRtcTransport, dgram        UDP / WebRTC DC
 0  Packet classification  protocol                        (demux STUN/RTP/RTCP)

 Cross-cutting:  crypto (key derivation), bytes (encoding),
                 types (contracts), diag + trace (observability)
```

### File Map

| File | Role |
|------|------|
| `src/lib/engine/node.ts` | Main engine: call lifecycle, signaling ingestion, relay control orchestration |
| `src/lib/engine/helpers.ts` | JID parsing, SSRC/stream plan builders, endpoint decoding, CONNECTION-ID derivation |
| `src/lib/engine/relay-setup.ts` | Transport application, relay controller spawning, media pipeline bootstrap |
| `src/lib/engine/e2e.ts` | E2E key derivation, downlink relocking, call key setup |
| `src/lib/media/mediaPipeline.ts` | Audio I/O pipeline: encoder → pacer → SRTP protect → relay send, and receive path |
| `src/lib/media/mlowWasmRtp.ts` | WASM-based MLow encoder (libopus_mlow via WASM) with ffmpeg PCM pre-decode |
| `src/lib/media/ffmpegRtp.ts` | ffmpeg-driven Opus RTP receiver (decode to PCM via loopback UDP) |
| `src/lib/media/rtpEngine.ts` | RTP send/receive engines with ROC tracking, WARP packetization |
| `src/lib/crypto/srtp.ts` | SRTP encrypt/unprotect (AES-128-CTR, HMAC-SHA1 auth), HBH key derivation |
| `src/lib/crypto/srtp1to1.ts` | 1:1 E2E SRTP key derivation (HKDF + AES-CM PRF), AES-CTR encrypt/decrypt |
| `src/lib/crypto/sframe.ts` | SFrame per-frame AES-GCM encryption for E2E group calls |
| `src/lib/crypto/warp.ts` | WARP extension framing (0xDEBE), audio-piggyback, message-integrity tags |
| `src/lib/protocol/protocol.ts` | Packet classification (STUN/DTLS/RTP/RTCP), parsers, builders, XOR-address encoding |
| `src/lib/protocol/relay.ts` | STUN relay protocol: allocate request/builder, protobuf stream subscriptions, message integrity |
| `src/lib/protocol/xmpp.ts` | XMPP call signaling parser (offer/preaccept/accept/ack/terminate/reject) + relay transport info |
| `src/lib/relay/relayController.ts` | State machine per relay endpoint: creating → allocated → bound → ready |
| `src/lib/relay/relayTransport.ts` | Transport stanza → relay-list-update conversion (base64 normalization) |
| `src/lib/relay/relayMedia.ts` | Slim SRTP bridge (uplink protect + downlink unprotect) |
| `src/lib/relay/RelayRtcTransport.mts` | WebRTC DataChannel transport to WhatsApp relay servers via @roamhq/wrtc |
| `src/lib/core/crypto.ts` | HKDF, HMAC, SHA-256, SSRC derivation (participant + relay stream), raw_e2e splitting |
| `src/lib/core/bytes.ts` | Byte utilities: hex/base64/UTF-8, concat, timing-safe comparison, big-endian read/write |
| `src/lib/core/types.ts` | TypeScript type definitions (VoipConfig, Callbacks, SignalingMessage, CallInfo, enums) |
| `src/lib/app/diag.ts` | Human-readable diagnostics: E2E key dump, SSRC plan, per-packet TX/RX logging (env-gated) |
| `src/lib/app/callTui.ts` | Live terminal UI for the test caller (status panel + event feed); verbose flag falls back to raw logs |
| `src/lib/app/trace.ts` | JSONL tracer (parity with WASM caller's tracer): markers, stanzas, relay packets, PCM |
| `src/lib/app/whatsapp-signaling.ts` | Baileys/XMPP bridge: JID helpers, BinaryNode rendering, Signal call-key encrypt/decrypt, stanza construction |
| `src/examples/baileys-real-call.mts` | Reference caller: Baileys auth ↔ engine bridge, dgram/wrtc relay transport, full call lifecycle + TUI |
| `src/examples/test-call-mlow.mts` | Thin wrapper that pins the MLow backend; takes `<target> [authDir] [audioFile]` + `--verbose` |
| `src/vendor/libopus-wasm/` | WASM libopus encoder bindings (libopus + SMPL/MLow extension) used by the MLow encoder path |
| `src/index.ts` | Public API exports |

---

## Call Flow (1:1 Audio Call)

### 1. Engine Setup

```ts
const voip = new WhatsAppVoipNode({
  audioSource: "path/to/audio.mp3",  // or "lavfi:sine=frequency=440"
  callbacks: {
    onLog: (level, msg) => console.log(msg),
    onCallEvent: (type, data) => { /* state changes */ },
    onAudioPlaybackData: (samples) => { /* decoded PCM */ },
  },
});
await voip.initialize();
voip.initVoipStack(selfPnJid, selfPnBareJid, selfLidJid);
```

### 2. Relay Transport Bridge

The engine needs a `send` callback that puts bytes onto the relay. Two transport options:

**Option A — Raw UDP (testing only):**
```ts
const socket = dgram.createSocket("udp4");
voip.setRelaySendCallback((packet, ip, port) => {
  socket.send(packet, port, ip);
});
socket.on("message", (msg, rinfo) => {
  voip.feedRelayDatagram(new Uint8Array(msg), rinfo.address, rinfo.port);
});
```

**Option B — WebRTC DataChannel (production):**
```ts
const relayTransport = new RelayRtcTransport({
  onTransportMessage: (data, ip, port) => {
    voip.feedRelayDatagram(new Uint8Array(data), ip, port);
  },
});
voip.setRelaySendCallback((packet, ip, port) => {
  relayTransport.send(Buffer.from(packet), ip, port);
});
// Feed relay-list updates from engine → transport
voip.callbacks.onCallEvent = (type, data) => {
  if (type === 156) relayTransport.updateRelayList(JSON.parse(data));
};
```

### 3. Call Key & Signaling

```ts
// Generate call key and ID
const callId = randomBytes(16).toString("hex").toUpperCase();
const sharedCallKey = randomBytes(32);

// For 1:1, call setE2ECallKey BEFORE the offer-ack arrives
voip.setE2ECallKey(sharedCallKey, selfLid, peerLid, peerDeviceLids);
// This sets up the AES-128-CTR E2E SRTP path instead of the HBH group path

voip.startCall({ callId, peerJid: peerLid, peerPn, isVideo: false });

// The engine emits an offer via onSignalingXmpp callback (JSON or XML).
// Encrypt the call key per destination with Signal and wrap in a <call>
// stanza sent through Baileys. Inbound <call> stanzas are forwarded to
// voip.handleSignalingMessage({ payload: xmlString }).
```

### 4. Media Flow

```
Audio Source (mp3/wav/lavfi)
    │
    ▼
[ffmpeg decode to PCM]
    │
    ▼
[MLow WASM Encoder] — libopus_mlow via WASM (MLow CTL 4050, 60ms frames)
    │
    ▼
[Pacer] — one frame per frame interval (60 ms MLow),
           drift-corrected monotonic clock
    │
    ▼
[RtpSendEngine] — sequence number, timestamp, SSRC, WARP extension
    │
    ▼
[SrtpContext.protectRtp] — AES-128-CTR encrypt, append WARP MI tag
    │
    ▼
[relaySendCallback] → UDP or WebRTC DataChannel → WhatsApp Relay
```

Inbound follows the reverse path:
```
WhatsApp Relay → [SRTP unprotect] → [rtpRecvEngine ROC tracking]
    → [ffmpeg decode] → PCM (Float32Array) → onAudioPlaybackData callback
```

---

## SRTP Encryption

### 1:1 E2E Path (AES-128-CTR)

Used for direct 1:1 calls. The call key (or `raw_e2e` from accept) is the IKM.

```
master = HKDF-SHA256(ikm = callKey[0:32], salt = zero32, info = senderLid_utf8, 46)

master_key  = master[0:16]
master_salt = master[16:30]   (14 bytes)

session_enc  = AES-CM-PRF(master_key, master_salt, label=0x00, 16)
session_auth = AES-CM-PRF(master_key, master_salt, label=0x01, 20)
session_salt = AES-CM-PRF(master_key, master_salt, label=0x02, 14)
```

Each direction uses the **sender's** device-qualified LID (e.g. `<sender-lid>:13@lid`) as HKDF info. The IV is built per RFC 3711 §4.1.1 from salt + SSRC + packet index.

No SRTP auth tag is appended — the WARP message-integrity tag handles hop-by-hop integrity.

### Group Call HBH Path (AES-128-CTR + HMAC-SHA1)

Two-stage HKDF cascade:
```
Stage 1: salt = HKDF(ikm=saltBase, salt=zero32, info=saltLabel, 32)
Stage 2: key  = HKDF(ikm=keyBase,  salt=salt,       info=keyLabel,  30)

key[0:16]  = encryption key
key[16:30] = authentication key (14 bytes)
salt[0:14] = master salt
```

Separate key sets for SRTP (bidirectional), uplink SRTCP, and downlink SRTCP. Auth tags are HMAC-SHA1 with the full 4-byte WARP MI tag appended to every RTP packet.

---

## WARP Framing

Every audio RTP packet carries WhatsApp's proprietary WARP extension:

```
[ RTP 12-byte header ]
[ WARP extension: 0xDEBE profile, N 32-bit words ]
[ Opus ciphertext (AES-128-CTR) ]
[ WARP MI tag: 4 bytes (or warp_mi_tag_len bytes) ]
```

The WARP extension is either:
- **Empty** (`debe 0000`): first 2 packets of the call
- **Audio piggyback** (`debe 0001 30 01 00 00`): packets #3 onward

The MI tag is `HMAC-SHA1(auth_key, header || ext || ciphertext || ROC_BE32)[0:warp_mi_tag_len]`.

WARP also defines three proprietary RTCP packet types:
- **PT 208 (TFB)**: Transport-feedback, carries the sender's RTP index
- **PT 209 (Stream Hello)**: Stream registration keepalive
- **PT 206 (AFB, FMT=15)**: Application-layer feedback

These are sent on a cadence alongside media to keep the relay stream registered.

---

## STUN Relay Protocol

### Message Types

| Type | Name | Direction | Purpose |
|------|------|-----------|---------|
| 0x0003 | Private Allocate | Client→Relay | Request relay resources with stream subscriptions |
| 0x0103 | Allocate Success | Relay→Client | Relay accepted the allocate |
| 0x0113 | Allocate Error | Relay→Client | Relay rejected (e.g. CONNECTION-ID mismatch) |
| 0x0001 | Binding Request | Relay→Client | Relay checks connectivity |
| 0x0101 | Binding Success | Client→Relay | Client responds to binding check |
| 0x0801 | Keepalive Indication | Client→Relay | Periodic keepalive (~1.1s interval) |

### Allocate Request Structure

```
STUN Header (msgType=0x0003, magicCookie=0x2112A442, transactionId[12])
Attribute: RELAY-TOKEN (0x4000)        — base64-decoded relay token
Attribute: STREAM-SUBSCRIPTION (0x4024) — protobuf-encoded stream list
Attribute: CONNECTION-ID (0x0016)       — 8-byte XOR-mapped relay address
Attribute: MESSAGE-INTEGRITY (0x0008)   — HMAC-SHA1 over packet body
```

### Stream Subscription Protobuf

```
message StreamSubscription {
  uint32 participant_index = 1;
  uint32 stream_index = 2;
  uint32 ssrc = 3;
}
// Repeated, each wrapped in field-1 length-delimited
```

The production plan uses 3 streams × 3 SSRCs = 9 entries (audio + 2 video streams).

### CONNECTION-ID

The 8-byte CONNECTION-ID is the STUN XOR-MAPPED-ADDRESS of the relay endpoint:

```
conn_id = 0x0001 || (port XOR 0x2112) || (IPv4 XOR 0x2112A442)
```

### Relay Controller State Machine

```
creating ──[send allocate]──► creating (retry every 500ms)
    │
    ▼ [receive 0x0103 or 0x0101]
allocated ──[receive bind request]──► bound
    │
    ▼ [start keepalive timer]
  bound ──► ready (emit 'ready' event → media pipeline starts)
    │
    ▼ [receive 0x0113 error]
allocate_error → close (relay is unusable, fail over to another)
```

---

## XMPP Call Signaling

### Stanza Flow (Caller Perspective)

```
Caller                              Server / Peer
  │                                     │
  ├─ <call><offer call-id=...> ────────►│  Engine emits via onSignalingXmpp
  │                                     │  Consumer wraps in <call>, encrypts
  │                                     │  <enc> payloads, sends via Baileys
  │                                     │
  │◄── <call><ack error=0> ──────────── ┤  Forwarded to handleSignalingMessage
  │    contains <relay><transport>      │  Engine extracts relay tokens, IPs
  │                                     │
  │◄── <call><preaccept> ─────────────--┤  
  │                                     │
  │◄── <call><accept call-id=...> ─────-┤  Peer answered
  │    contains <raw_e2e>, <relay>      │  E2E keys derived, relay targets set
  │                                     │
  │    [media flows both directions]    │
  │                                     │
  ├─ <call><terminate> ───────────────-►│  Caller hangs up
  │                                     │
```

### Transport Stanza Structure

```xml
<relay peer_pid="1" self_pid="0" uuid="...">
  <transport>
    <conn_id>hex_or_decimal</conn_id>
    <key>base64_key_material</key>
    <token id="0">base64_relay_token</token>
    <hbh_key>base64_hbh_key</hbh_key>
    <warp_mi_tag_len>4</warp_mi_tag_len>
    <te>
      <endpoint addr="1.2.3.4" port="3478" relay_id="0" token_id="0"
                relay_name="relay-name">
        0a01020304da0d  <!-- hex-encoded 6 or 18 byte endpoint blob -->
      </endpoint>
    </te>
  </transport>
</relay>
```

---

## Audio Encoding

The engine uses WhatsApp's proprietary **MLow** codec (an SMPL/CELP extension of
libopus) through the vendored WASM bindings in `src/vendor/libopus-wasm/`.
MLow reuses the Opus TOC byte convention but assigns different meanings: a
`0x50` MLow packet decodes to **960 samples / 60 ms** (not the 40 ms a vanilla
Opus decoder assumes), and the decoder must be put into MLow mode with
`opus_decoder_ctl(dec, 4050, 1)`.

### Audio Source

The `audioSource` config accepts:
- File path: `song.mp3`, `/path/to/audio.wav`
- lavfi source: `lavfi:sine=frequency=440`
- Any format ffmpeg can decode

## MLow Env Vars

| Variable | Default | Description |
|----------|---------|-------------|
| `CALL_MLOW_BITRATE_BPS` | 25000 | MLow encoder target bitrate |
| `CALL_AUDIO_CHANNELS` | 1 | Audio channels |
| `CALL_AUDIO_FILTER` | (ffmpeg -af chain) | Pre-encode audio filter |
| `CALL_AUDIO_PIGGYBACK` | 0 | Enable WARP audio piggyback extension |
| `CALL_AUDIO_SEND_EVERY_N` | 1 | Send every Nth frame (throttle) |

---

## Key Derivation Reference

### Participant SSRC

```
SSRC = HKDF-SHA256(ikm=callId_utf8, salt=slotWord_LE32, info=lid_utf8, 4) as BE32
```

### Relay Stream SSRCs (9-entry plan)

Slot words: `[0, 1, 4, 2, 3, 5, 7, 8, 6]` — same HKDF as participant SSRC.

### E2E SFrame Key

```
key = HKDF-SHA256(ikm=raw_e2e[0:32], salt=raw_e2e[32:], info="e2e sframe key", 32)
```

### Fingerprint HMAC

```
key = HKDF(ikm=raw_e2e[0:32], salt=raw_e2e[32:],
           info="data-channel cert fingerprint hmac", 32)
hmac = HMAC-SHA256(key, fingerprint_bytes)
```

---

## Environment Variable Reference

### Call Control
| Variable | Default | Description |
|----------|---------|-------------|
| `CALL_DURATION_MS` | 30000 | Auto-hangup after N ms |
| `CALL_ACCEPT_WAIT_MS` | 60000 | Max wait for peer accept |
| `CALL_AUDIO_SOURCE` | (from config) | Audio source for outbound media |

### Relay Transport
| Variable | Default | Description |
|----------|---------|-------------|
| `CALL_RELAY_KEEPALIVE_INTERVAL_MS` | 1100 | Keepalive period |
| `CALL_RELAY_PING_INTERVAL_MS` | 5000 | Ping period (disabled by default) |
| `CALL_RELAY_ALLOCATE_RETRY_MS` | 500 | Allocate retry interval |
| `CALL_RELAY_PORT_MODE` | original | `original` or `web` port mapping |

### Diagnostics & logging
| Variable | Default | Description |
|----------|---------|-------------|
| `CALL_VERBOSE` | 0 | `1` disables the live TUI and prints raw `[real-call]` + `[diag]` logs (same as `--verbose`/`-v`) |
| `CALL_DIAG` | 1 (0 under TUI) | Enable the per-packet diagnostic stream. Auto-set to `0` when the TUI is active unless you set it explicitly. Read lazily so it can be toggled after import. |
| `CALL_DIAG_VERBOSE` | 0 | Log every packet instead of the rate-limited sample |
| `CALL_DIAG_SAMPLE` | 50 | Sample 1-in-N packets after the first few |
| `CALL_DUMP_NODE_TRACE` | (enabled) | JSONL trace output (see `trace.ts`) |
| `CALL_DUMP_OPUS_FRAMES_PATH` | (none) | Dump bare Opus/MLow frames (JSONL: ts/seq/len/hex) — useful to verify the stream decodes |
| `CALL_DUMP_RELAY_PACKETS_PATH` | (none) | Dump relay RTC packets to file |
| `CALL_REPLAY_OPUS_PATH` | (none) | Replay a captured frame stream instead of encoding live |
| `CALL_REPLAY_LOOP` | 0 | Loop the replay stream |

---

## MLow WASM Backend

The MLow encoder runs fully in-process through the vendored WASM bindings in
`src/vendor/libopus-wasm/` (libopus compiled with the SMPL/MLow extension,
exposed as `libopus_mlow-wasm`). No native libraries, no Docker, no external
processes: `opusGlobalCreate()` initializes the SMPL global tables once, the
encoder/decoder are created with `useSmpl: true` (MLow mode, CTL 4050), and
16 kHz mono PCM comes out as 60 ms / 960-sample MLow packets.

`MlowWasmRtpSender` (`src/lib/media/mlowWasmRtp.ts`):

1. Pre-decodes the source with ffmpeg to clean 16 kHz mono float PCM.
2. Encodes the entire source into 60 ms MLow frames in memory.
3. Pushes frames out one at a time at the 60 ms interval (bursty delivery
   makes playback drift or sound slow).

The earlier Docker/QEMU backend (ARM64 `libopus_mlow.so` under QEMU
emulation) was replaced by this WASM path and no longer ships with this
repository.

---

## Test Command

The simplest way to place a call is the `test:call` script, which pins the MLow
backend and takes the target, auth dir, and audio file as positional args:

```bash
npm run test:call -- <target> [authDir] [audioFile]
# or directly:
npx tsx src/examples/test-call-mlow.mts <target> [authDir] [audioFile]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `target` | (required) | Phone number to call (digits; non-digits ignored) |
| `authDir` | `./auth` | Baileys multi-file auth state directory |
| `audioFile` | `lavfi:sine=frequency=440` | Audio source for ffmpeg, or a `lavfi:` spec |

Examples:

```bash
npm run test:call -- <number>                          # MLow + default tone + live TUI
npm run test:call -- <number> ./auth ./song.mp3        # custom auth + audio file
npm run test:call -- <number> --verbose                # raw logs instead of TUI
```

### Live TUI vs verbose logs

By default a compact, self-redrawing **terminal UI** shows the call state
(connecting / ringing / active / ended), peer LID, callId, the generated SSRC,
the relay table with live RTTs, media sent/received counters, and a small feed
of notable events. Pass `--verbose` / `-v` (or set `CALL_VERBOSE=1`) to disable
the TUI and stream the raw `[real-call]` + `[diag]` engine logs instead. On a
non-TTY (piped / CI) the TUI degrades to compact `[call]` status lines.

### Choosing a different audio source

Both examples take the outbound audio from `CALL_AUDIO_SOURCE` (or the
positional `audioFile` argument). Any source ffmpeg can decode works — files,
`lavfi:` generators, etc. — and is resampled to 16 kHz mono s16le before MLow
encoding. Tune the encoder with `CALL_MLOW_BITRATE_BPS` (default 25000),
`CALL_AUDIO_CHANNELS`, `CALL_AUDIO_PIGGYBACK`, `CALL_AUDIO_SEND_EVERY_N`, and
`CALL_AUDIO_FILTER` (ffmpeg `-af` chain) — see the env var reference above.
