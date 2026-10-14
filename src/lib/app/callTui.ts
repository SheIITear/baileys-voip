/**
 * ============================================================================
 * STACK LAYER 8 — Application / presentation (TUI)
 * ============================================================================
 *
 * A self-redrawing terminal UI for the test caller: phase badge, peer/callId/
 * SSRC, relay table with live RTTs, media counters and an event feed. Falls back
 * to plain lines on non-TTY and is bypassed entirely in verbose mode.
 *
 * Why: a readable live view of the call without the raw per-packet log firehose.
 * Consumes state pushed by the example; produces console output only.
 */
/**
 * Minimal terminal UI for the WhatsApp test caller.
 *
 * Renders a compact, self-redrawing status panel (call state, peer, relays +
 * RTTs, SSRC, RTP sent/received counters, audio samples) plus a small scrolling
 * feed of notable events. When disabled (verbose mode or non-TTY), every update
 * falls through to plain `console.log` lines so nothing is lost in logs/CI.
 *
 * Enable verbose (raw) logging via `CALL_VERBOSE=1` or the `--verbose` flag;
 * the TUI is then bypassed entirely and the underlying engine diagnostics
 * (`CALL_DIAG`) print as usual.
 */
type CallPhase =
  | "init"
  | "connecting"
  | "ringing"
  | "active"
  | "ending"
  | "ended"
  | "failed";

interface RelayView {
  name: string;
  ip: string;
  port: number;
  rttMs?: number;
  state?: string;
}

interface CallState {
  phase: CallPhase;
  target: string;
  selfLid?: string;
  peerLid?: string;
  callId?: string;
  senderSsrc?: number;
  peerSsrcs: number[];
  relays: Map<string, RelayView>;
  rtpSent: number;
  rtpRecv: number;
  octRecv: number;
  recvSamples: number;
  nonZeroSamples: number;
  startedAt?: number;
  holdMs?: number;
  note?: string;
}

const ESC = "\x1b[";
const color = (code: string, s: string) => `${ESC}${code}m${s}${ESC}0m`;
const dim = (s: string) => color("2", s);
const bold = (s: string) => color("1", s);
const green = (s: string) => color("32", s);
const yellow = (s: string) => color("33", s);
const red = (s: string) => color("31", s);
const cyan = (s: string) => color("36", s);
const gray = (s: string) => color("90", s);

const PHASE_BADGE: Record<CallPhase, string> = {
  init: gray("● INIT"),
  connecting: yellow("● CONNECTING"),
  ringing: yellow("● RINGING"),
  active: green("● ACTIVE"),
  ending: yellow("● ENDING"),
  ended: gray("● ENDED"),
  failed: red("● FAILED"),
};

const ssrcHex = (n?: number) =>
  n === undefined ? "—" : "0x" + (n >>> 0).toString(16).padStart(8, "0");

const fmtDuration = (ms: number): string => {
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  return `${m}:${String(s % 60).padStart(2, "0")}`;
};

export class CallTui {
  #enabled: boolean;
  #logStructured: boolean;
  #isTty: boolean;
  #state: CallState;
  #feed: string[] = [];
  #maxFeed = 6;
  #timer: ReturnType<typeof setInterval> | null = null;
  #lastLineCount = 0;

  constructor(opts: { target: string; enabled?: boolean; verbose?: boolean }) {
    this.#isTty = Boolean(process.stdout.isTTY);
    const verbose = opts.verbose === true || opts.enabled === false;
    this.#enabled = !verbose && this.#isTty;
    this.#logStructured = !verbose;
    this.#state = {
      phase: "init",
      target: opts.target,
      peerSsrcs: [],
      relays: new Map(),
      rtpSent: 0,
      rtpRecv: 0,
      octRecv: 0,
      recvSamples: 0,
      nonZeroSamples: 0,
    };
  }

  isLive(): boolean { return this.#enabled; }

  start(): void {
    if (!this.#enabled) return;
    process.stdout.write(`${ESC}?25l`);
    this.#timer = setInterval(() => this.#render(), 250);
    this.#render();
  }

  phase(phase: CallPhase, note?: string): void {
    this.#state.phase = phase;
    if (note) this.#state.note = note;
    if (phase === "active" && !this.#state.startedAt) this.#state.startedAt = Date.now();
    if (!this.#enabled && this.#logStructured) this.#plain(`state=${phase}${note ? ` (${note})` : ""}`);
    else this.#render();
  }

  setHold(ms: number): void { this.#state.holdMs = ms; }

  identity(fields: { selfLid?: string; peerLid?: string; callId?: string }): void {
    Object.assign(this.#state, fields);
    if (!this.#enabled && this.#logStructured) {
      this.#plain(`identity self=${fields.selfLid ?? "?"} peer=${fields.peerLid ?? "?"} callId=${fields.callId ?? "?"}`);
    }
  }

  ssrcPlan(senderSsrc: number, peerSsrcs: number[]): void {
    this.#state.senderSsrc = senderSsrc;
    this.#state.peerSsrcs = peerSsrcs;
    if (!this.#enabled && this.#logStructured) {
      this.#plain(`ssrc sender=${ssrcHex(senderSsrc)} peer=[${peerSsrcs.map(ssrcHex).join(",")}]`);
    }
  }

  relay(id: string, view: Partial<RelayView>): void {
    const cur = this.#state.relays.get(id) || { name: id, ip: "", port: 0 };
    this.#state.relays.set(id, { ...cur, ...view });
    if (!this.#enabled && this.#logStructured && (view.rttMs !== undefined || view.state)) {
      const r = this.#state.relays.get(id)!;
      this.#plain(`relay ${r.name || id} ${r.ip}:${r.port} rtt=${r.rttMs ?? "?"}ms ${r.state ?? ""}`.trim());
    }
  }

  stats(s: { rtpSent: number; rtpRecv: number; octRecv: number }): void {
    this.#state.rtpSent = s.rtpSent;
    this.#state.rtpRecv = s.rtpRecv;
    this.#state.octRecv = s.octRecv;
    if (!this.#enabled && this.#logStructured) {
      this.#plain(`stats sent=${s.rtpSent} recv=${s.rtpRecv} octRecv=${s.octRecv}`);
    }
  }

  audio(recvSamples: number, nonZeroSamples: number): void {
    this.#state.recvSamples = recvSamples;
    this.#state.nonZeroSamples = nonZeroSamples;
  }

  event(msg: string): void {
    const line = `${dim(new Date().toLocaleTimeString())} ${msg}`;
    this.#feed.push(line);
    while (this.#feed.length > this.#maxFeed) this.#feed.shift();
    if (!this.#enabled) { if (this.#logStructured) this.#plain(msg); }
    else this.#render();
  }

  warn(msg: string): void { this.event(yellow(`⚠ ${msg}`)); }
  fail(msg: string): void { this.event(red(`✖ ${msg}`)); }

  stop(): void {
    if (this.#timer) {
      clearInterval(this.#timer);
      this.#timer = null;
    }
    if (this.#enabled) {
      this.#render();
      process.stdout.write(`${ESC}?25h\n`);
    }
  }

  #plain(msg: string): void {
    console.log(`[call] ${msg}`);
  }

  #render(): void {
    if (!this.#enabled) return;
    const lines = this.#buildLines();
    let out = "";
    if (this.#lastLineCount > 0) out += `${ESC}${this.#lastLineCount}A`;
    for (const l of lines) out += `${ESC}2K${l}\n`;
    process.stdout.write(out);
    this.#lastLineCount = lines.length;
  }

  #buildLines(): string[] {
    const s = this.#state;
    const lines: string[] = [];

    const elapsed =
      s.phase === "active" && s.startedAt ? ` ${cyan(fmtDuration(Date.now() - s.startedAt))}` : "";
    lines.push(`${bold("WhatsApp Call")}  ${PHASE_BADGE[s.phase]}${elapsed}`);
    lines.push(`  ${dim("target")} ${s.target}   ${dim("peer")} ${s.peerLid ?? "—"}`);
    lines.push(
      `  ${dim("callId")} ${s.callId ?? "—"}   ${dim("ssrc")} ${ssrcHex(s.senderSsrc)}` +
        (s.peerSsrcs.length ? ` ${dim("←")} ${s.peerSsrcs.map(ssrcHex).join(",")}` : ""),
    );

    if (s.relays.size) {
      lines.push(`  ${dim("relays")}`);
      for (const r of s.relays.values()) {
        const rtt =
          r.rttMs === undefined ? gray("    ?ms")
            : (r.rttMs <= 60 ? green : r.rttMs <= 150 ? yellow : red)(`${String(r.rttMs).padStart(5)}ms`);
        const st = r.state ? gray(` ${r.state}`) : "";
        lines.push(`    ${(r.name || "relay").padEnd(8)} ${(r.ip + ":" + r.port).padEnd(22)} ${rtt}${st}`);
      }
    }

    const audioPct = s.recvSamples > 0 ? Math.round((s.nonZeroSamples / s.recvSamples) * 100) : 0;
    lines.push(
      `  ${dim("media")}  ${green("▲")} sent ${bold(String(s.rtpSent))}   ` +
        `${cyan("▼")} recv ${bold(String(s.rtpRecv))}  ${dim(`(${s.octRecv}B`)}` +
        (s.recvSamples ? dim(`, audio ${audioPct}%)`) : dim(")")),
    );

    if (this.#feed.length) {
      lines.push(dim("  " + "-".repeat(6)));
      for (const f of this.#feed) lines.push(`  ${f}`);
    }

    return lines;
  }
}
