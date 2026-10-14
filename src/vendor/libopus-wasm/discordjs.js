import { Buffer } from "node:buffer";
import { createDecoder, createEncoder } from "./index.js";
export class OpusEncoder {
    channels;
    rate;
    ready;
    #decoder;
    #encoder;
    #freed = false;
    #initError;
    constructor(rate = 48_000, channels = 2) {
        this.rate = rate;
        this.channels = channels;
        this.ready = Promise.all([
            createEncoder({
                channels: channels,
                sampleRate: rate,
            }),
            createDecoder({
                channels: channels,
                sampleRate: rate,
            }),
        ]).then(([encoder, decoder]) => {
            if (this.#freed) {
                encoder.free();
                decoder.free();
                return;
            }
            this.#encoder = encoder;
            this.#decoder = decoder;
        }).catch((error) => {
            this.#initError = error;
            throw error;
        });
        this.ready.catch(() => undefined);
    }
    static async create(rate = 48_000, channels = 2) {
        const encoder = new OpusEncoder(rate, channels);
        await encoder.ready;
        return encoder;
    }
    encode(buf) {
        const encoder = this.#requireEncoder();
        const frameSize = inferFrameSize(buf.byteLength, this.channels);
        return Buffer.from(encoder.encode(buf, { frameSize }));
    }
    decode(buf) {
        const decoder = this.#requireDecoder();
        const pcm = decoder.decode(buf);
        return Buffer.from(pcm.buffer, pcm.byteOffset, pcm.byteLength);
    }
    applyEncoderCTL(ctl, value) {
        this.#requireEncoder().encoderCtl(ctl, value);
    }
    applyDecoderCTL(ctl, value) {
        this.#requireDecoder().decoderCtl(ctl, value);
    }
    setBitrate(bitrate) {
        this.#requireEncoder().setBitrate(bitrate);
    }
    getBitrate() {
        return this.#requireEncoder().getBitrate();
    }
    setFEC(enabled) {
        this.#requireEncoder().setFec(enabled);
    }
    setPLP(percentage) {
        this.#requireEncoder().setPacketLossPercent(percentage);
    }
    free() {
        if (this.#freed) {
            return;
        }
        this.#freed = true;
        this.#encoder?.free();
        this.#decoder?.free();
    }
    [Symbol.dispose]() {
        this.free();
    }
    #requireEncoder() {
        this.#throwInitErrorIfAny();
        if (!this.#encoder || this.#freed) {
            throw new Error("OpusEncoder is not ready; await encoder.ready or use OpusEncoder.create()");
        }
        return this.#encoder;
    }
    #requireDecoder() {
        this.#throwInitErrorIfAny();
        if (!this.#decoder || this.#freed) {
            throw new Error("OpusEncoder is not ready; await encoder.ready or use OpusEncoder.create()");
        }
        return this.#decoder;
    }
    #throwInitErrorIfAny() {
        if (!this.#initError) {
            return;
        }
        throw new Error("OpusEncoder failed to initialize", { cause: this.#initError });
    }
}
function inferFrameSize(byteLength, channels) {
    const frameSize = byteLength / 2 / channels;
    if (!Number.isInteger(frameSize) || frameSize <= 0) {
        throw new RangeError("PCM buffer length must contain whole signed 16-bit samples for each channel");
    }
    return frameSize;
}
