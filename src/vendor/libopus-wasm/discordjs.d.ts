import { Buffer } from "node:buffer";
export declare class OpusEncoder {
    #private;
    readonly channels: number;
    readonly rate: number;
    readonly ready: Promise<void>;
    constructor(rate?: number, channels?: number);
    static create(rate?: number, channels?: number): Promise<OpusEncoder>;
    encode(buf: Buffer | Uint8Array): Buffer;
    decode(buf: Buffer | Uint8Array): Buffer;
    applyEncoderCTL(ctl: number, value: number): void;
    applyDecoderCTL(ctl: number, value: number): void;
    setBitrate(bitrate: number): void;
    getBitrate(): number;
    setFEC(enabled: boolean): void;
    setPLP(percentage: number): void;
    free(): void;
    [Symbol.dispose](): void;
}
//# sourceMappingURL=discordjs.d.ts.map