/**
 * ============================================================================
 * CROSS-CUTTING — Observability (human-readable diagnostics)
 * ============================================================================
 *
 * Terse, grep-able stderr/stdout diagnostics for the E2E SRTP / WARP path: one-
 * shot key/SSRC dumps and rate-limited per-packet TX/RX lines. Env flags are read
 * lazily so the TUI can silence the stream after import.
 *
 * Why: confirm the media crypto is correct and spot SSRC/MI/decrypt issues fast.
 * Not the JSONL tracer (see trace.ts).
 */
/**
 * Lightweight, human-readable diagnostics for the 1:1 E2E SRTP / WARP path.
 *
 * Goal: when you run a real call, the console emits exactly the facts needed
 * to confirm the media crypto is correct and to spot any remaining issue
 * (wrong/short LID, SSRC mismatch, MI-tag failure, undecryptable inbound
 * audio, etc.). This is NOT the JSONL tracer (`trace.ts`) — it's a terse,
 * grep-able stderr/stdout stream.
 *
 * Env knobs:
 *   CALL_DIAG=0          turn diagnostics OFF (default ON)
 *   CALL_DIAG_VERBOSE=1  log EVERY packet instead of the rate-limited sample
 *   CALL_DIAG_SAMPLE=N   sample 1-in-N packets after the first few (default 50)
 */
// Read env lazily so callers can toggle diagnostics (e.g. the TUI silencing the
// per-packet stream) after this module has been imported. ESM import hoisting
// means a top-level `const ENABLED = ...` would latch the value too early.
const isEnabled = (): boolean => process.env.CALL_DIAG !== "0";
const isVerbose = (): boolean => process.env.CALL_DIAG_VERBOSE === "1";
const sampleRate = (): number => Number(process.env.CALL_DIAG_SAMPLE) || 50;
const FIRST_N = 5;

const counters: Record<string, number> = {};

const hex = (b: Uint8Array | undefined, max = 9999): string =>
  b ? Buffer.from(b.buffer, b.byteOffset, Math.min(b.byteLength, max)).toString("hex") : "";

/** Should this channel log on its `n`-th (1-based) call? First few + sampled. */
const shouldLog = (channel: string): boolean => {
  if (!isEnabled()) return false;
  const n = (counters[channel] = (counters[channel] || 0) + 1);
  if (isVerbose()) return true;
  return n <= FIRST_N || n % sampleRate() === 0;
};

const emit = (line: string): void => {
  if (!isEnabled()) return;
  // eslint-disable-next-line no-console
  console.log(`[diag] ${line}`);
};

/** Always-on structured line (not rate limited) — for setup / one-shot facts. */
export const diag = (tag: string, fields: Record<string, unknown>): void => {
  if (!isEnabled()) return;
  emit(`${tag} ${fmt(fields)}`);
};

/** Always-on warning line. */
export const diagWarn = (tag: string, message: string, fields: Record<string, unknown> = {}): void => {
  if (!isEnabled()) return;
  emit(`WARN ${tag}: ${message} ${fmt(fields)}`);
};

const fmt = (fields: Record<string, unknown>): string =>
  Object.entries(fields)
    .map(([k, v]) => {
      if (v instanceof Uint8Array) return `${k}=${hex(v)}`;
      if (typeof v === "number") return `${k}=${v}`;
      return `${k}=${String(v)}`;
    })
    .join(" ");

/**
 * One-shot dump of the derived 1:1 E2E SRTP session material for one
 * direction. Lets you eyeball the exact keys/salt the peer must match.
 */
export const diagE2EKeys = (
  direction: "uplink" | "downlink",
  info: {
    lid: string;
    cipherKey: Uint8Array;
    authKey: Uint8Array;
    salt: Uint8Array;
    warpMiTagLen: number;
  },
): void => {
  if (!isEnabled()) return;
  emit(
    `e2e-srtp ${direction} lid="${info.lid}" sessionEnc=${hex(info.cipherKey)} ` +
      `sessionAuth=${hex(info.authKey)} sessionSalt=${hex(info.salt)} warpMiTagLen=${info.warpMiTagLen}`,
  );
  if (!info.lid.includes(":")) {
    diagWarn(
      "e2e-srtp",
      `${direction} LID is NOT device-qualified — the native app derives keys with the ` +
        `device-qualified LID (e.g. "user:42@lid"). A bare LID will make the peer unable ` +
        `to decrypt this direction.`,
      { lid: info.lid },
    );
  }
};

/** One-shot dump of the SSRC plan so RX SSRCs can be matched against it. */
export const diagSsrcPlan = (fields: {
  callId: string;
  selfLid: string;
  peerLid: string;
  senderSsrc: number;
  expectedSelfSsrcs: number[];
  expectedPeerSsrcs: number[];
}): void => {
  if (!isEnabled()) return;
  const h = (n: number) => "0x" + (n >>> 0).toString(16).padStart(8, "0");
  emit(
    `ssrc-plan callId=${fields.callId} senderSsrc=${h(fields.senderSsrc)} ` +
      `self[${fields.selfLid}]=${fields.expectedSelfSsrcs.map(h).join(",")} ` +
      `peer[${fields.peerLid}]=${fields.expectedPeerSsrcs.map(h).join(",")}`,
  );
};

/** Per-packet TX log (rate-limited). */
export const diagTx = (fields: {
  seq: number;
  ssrc: number;
  roc: number;
  extProfile: number;
  payloadLen: number;
  opusToc?: number;
  miTag: Uint8Array;
  full?: Uint8Array;
}): void => {
  if (!shouldLog("tx")) return;
  emit(
    `tx seq=${fields.seq} ssrc=0x${(fields.ssrc >>> 0).toString(16)} roc=${fields.roc} ` +
      `ext=0x${fields.extProfile.toString(16)} opusLen=${fields.payloadLen} opusToc=0x${((fields.opusToc??-1)>>>0).toString(16)} mi=${hex(fields.miTag)}` +
      (fields.full ? ` wire=${hex(fields.full)}` : ""),
  );
};

/** Per-packet RX log (rate-limited). */
export const diagRx = (fields: {
  ssrc: number;
  seq: number;
  roc: number;
  len: number;
  miOk: boolean | null;
  ssrcExpected: boolean | null;
  decryptOk: boolean;
  opusTocHex?: string;
  error?: string;
}): void => {
  if (!shouldLog("rx")) return;
  const miStr = fields.miOk === null ? "n/a" : fields.miOk ? "OK" : "FAIL";
  const ssrcStr = fields.ssrcExpected === null ? "?" : fields.ssrcExpected ? "known" : "UNKNOWN";
  emit(
    `rx ssrc=0x${(fields.ssrc >>> 0).toString(16)}(${ssrcStr}) seq=${fields.seq} roc=${fields.roc} ` +
      `len=${fields.len} mi=${miStr} decrypt=${fields.decryptOk ? "OK" : "FAIL"}` +
      (fields.opusTocHex ? ` opusToc=${fields.opusTocHex}` : "") +
      (fields.error ? ` err="${fields.error}"` : ""),
  );
  if (fields.ssrcExpected === false) {
    diagWarn("rx", "inbound SSRC is not in the derived peer-SSRC plan — peer may be using a different device LID than expected", {
      ssrc: "0x" + (fields.ssrc >>> 0).toString(16),
    });
  }
  if (fields.miOk === false) {
    diagWarn("rx", "WARP MI tag did NOT verify with the downlink auth key — wrong key derivation or wrong direction LID", {});
  }
};

export const diagEnabled = (): boolean => isEnabled();
