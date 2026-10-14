/**
 * Test caller: places a real WhatsApp 1:1 call and streams an audio file to the
 * callee, encoded with the WhatsApp MLow codec (WASM, no Docker).
 *
 * Usage:
 *   npm run test:call -- <target> [authDir] [audioFile]
 *   npx tsx src/examples/test-call-mlow.mts <target> [authDir] [audioFile]
 *
 * Arguments:
 *   target      phone number to call (digits; non-digits ignored).     (required)
 *   authDir     Baileys multi-file auth state directory.   (default: ./auth)
 *   audioFile   audio source for ffmpeg (mp3/wav/... or lavfi: spec).
 *               (default: lavfi:sine=frequency=440)
 *
 * Env knobs (forwarded to the underlying engine):
 *   CALL_DURATION_MS        auto-hangup after N ms (default 30_000)
 *   CALL_MLOW_BITRATE_BPS   MLow VBR target (default 25000)
 *
 * Flags:
 *   --verbose, -v           disable the live TUI and print raw engine logs
 *
 * @author ShellTear
 */
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const PROJECT_DIR = resolve(HERE, "../..");

const DEFAULT_AUTH_DIR = resolve(PROJECT_DIR, "auth");
const DEFAULT_AUDIO = "lavfi:sine=frequency=440";

const rawArgs = process.argv.slice(2);
const flags = rawArgs.filter((a) => a.startsWith("-"));
const positionals = rawArgs.filter((a) => !a.startsWith("-"));

const [rawTarget, rawAuth, rawAudio] = positionals;
const target = (rawTarget || "").replace(/\D/g, "");
if (!target) {
  console.error(
    "Usage: npm run test:call -- <target> [authDir] [audioFile]\n" +
      "  --verbose, -v    raw logs mode\n" +
      "  target           phone number to call (required)\n" +
      "  authDir          Baileys auth state dir         (default: ./auth)\n" +
      "  audioFile        audio source for ffmpeg        (default: lavfi:sine=frequency=440)",
  );
  process.exit(2);
}

const authDir = rawAuth ? resolve(process.cwd(), rawAuth) : DEFAULT_AUTH_DIR;
if (!existsSync(authDir)) {
  console.error(`[test-call] auth dir not found: ${authDir}`);
  process.exit(1);
}

let audioSource: string;
if (rawAudio) {
  audioSource = rawAudio.startsWith("lavfi:")
    ? rawAudio
    : resolve(process.cwd(), rawAudio);
} else {
  audioSource = DEFAULT_AUDIO;
}
if (!audioSource.startsWith("lavfi:") && !existsSync(audioSource)) {
  console.error(`[test-call] audio source not found: ${audioSource}`);
  process.exit(1);
}

process.env.CALL_AUDIO_SOURCE = audioSource;
process.env.CALL_MLOW_BITRATE_BPS ??= "25000";

process.argv = [process.argv[0]!, process.argv[1]!, authDir, target, ...flags];

console.log(
  `[test-call] auth=${authDir} -> calling ${target}, streaming ${audioSource} via mlow-wasm`,
);

await import("./baileys-real-call.mts");
