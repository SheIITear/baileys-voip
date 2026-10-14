export declare const Application: {
    readonly Voip: 2048;
    readonly Audio: 2049;
    readonly RestrictedLowDelay: 2051;
};
export declare const Signal: {
    readonly Auto: -1000;
    readonly Voice: 3001;
    readonly Music: 3002;
};
export declare const Bitrate: {
    readonly Auto: -1000;
    readonly Max: -1;
};
export declare const Bandwidth: {
    readonly Narrowband: 1101;
    readonly Mediumband: 1102;
    readonly Wideband: 1103;
    readonly Superwideband: 1104;
    readonly Fullband: 1105;
};
export declare const EncoderCtl: {
    readonly SetApplication: 4000;
    readonly SetBitrate: 4002;
    readonly SetMaxBandwidth: 4004;
    readonly SetVbr: 4006;
    readonly SetBandwidth: 4008;
    readonly SetComplexity: 4010;
    readonly SetInBandFec: 4012;
    readonly SetPacketLossPercent: 4014;
    readonly SetDtx: 4016;
    readonly SetVbrConstraint: 4020;
    readonly SetForceChannels: 4022;
    readonly SetSignal: 4024;
    readonly SetLsbDepth: 4036;
    readonly SetExpertFrameDuration: 4040;
    readonly SetPredictionDisabled: 4042;
    readonly SetPhaseInversionDisabled: 4046;
    readonly SetUseSmpl: 4050;
    readonly SetEncHpCutoff: 4052;
    readonly SetSecondaryComplexity: 4054;
    readonly SetSecondaryBitrate: 4056;
    readonly SetUseLpcPostfilter: 4058;
    readonly SetMlowSubframeImp: 4060;
    readonly SetMlowUseSpActFlat: 4062;
    readonly SetMlowVadNlUpdSpeed: 4064;
    readonly SetMlowVadNonBinary: 4066;
    readonly SetMlowVadHpSharpness: 4068;
    readonly SetMlowUseFecRateComp: 4070;
};
export declare const DecoderCtl: {
    readonly SetGain: 4034;
    readonly SetPhaseInversionDisabled: 4046;
    readonly SetUseSmpl: 4050;
    readonly SetUseLpcPostfilter: 4058;
};
export type Application = (typeof Application)[keyof typeof Application];
export type Signal = (typeof Signal)[keyof typeof Signal];
export type Bitrate = number | "auto" | "max";
export type Bandwidth = (typeof Bandwidth)[keyof typeof Bandwidth];
export type SampleRate = 8000 | 12000 | 16000 | 24000 | 48000;
export type ChannelCount = 1 | 2;
export type CodecOptions = {
    channels?: ChannelCount;
    sampleRate?: SampleRate;
};
export type EncoderOptions = CodecOptions & {
    application?: Application;
    bitrate?: Bitrate;
    complexity?: number;
    dtx?: boolean;
    fec?: boolean;
    frameSize?: number;
    maxBandwidth?: Bandwidth;
    packetLossPercent?: number;
    signal?: Signal;
    useSmpl?: boolean;
    vbr?: boolean;
    vbrConstraint?: boolean;
};
export type DecoderOptions = CodecOptions & {
    maxFrameSize?: number;
    useSmpl?: boolean;
};
export type DecodeOptions = {
    decodeFec?: boolean;
    frameSize?: number;
    maxFrameSize?: number;
};
export type EncodeOptions = {
    frameSize?: number;
    maxPacketBytes?: number;
};
export type PacketInfoOptions = {
    sampleRate?: SampleRate;
};
export type OpusPacketInfo = {
    readonly bandwidth: Bandwidth;
    readonly channels: ChannelCount;
    readonly durationMs: number;
    readonly frames: number;
    readonly samples: number;
    readonly samplesPerFrame: number;
    readonly sampleRate: SampleRate;
};
export type MlowPacketInfo = {
    readonly bandwidth: Bandwidth;
    readonly channels: ChannelCount;
    readonly durationMs: number;
    readonly frames: number;
    readonly samples: number;
    readonly samplesPerFrame: number;
    readonly sampleRate: SampleRate;
};
export type OpusEncoderHandle = {
    readonly application: Application;
    readonly channels: ChannelCount;
    readonly frameSize: number;
    readonly sampleRate: SampleRate;
    encode(pcm: Int16Array | Uint8Array, options?: EncodeOptions): Uint8Array;
    encodeFloat(pcm: Float32Array, options?: EncodeOptions): Uint8Array;
    encodeFrames(frames: readonly (Int16Array | Uint8Array)[], options?: EncodeOptions): Uint8Array[];
    encodeFloatFrames(frames: readonly Float32Array[], options?: EncodeOptions): Uint8Array[];
    encodeSecondary(options?: EncodeOptions): Uint8Array;
    encoderCtl(request: number, value: number): void;
    free(): void;
    getBitrate(): number;
    getInDtx(): boolean;
    getLookahead(): number;
    setBitrate(bitrate: Bitrate): void;
    setComplexity(complexity: number): void;
    setDtx(enabled: boolean): void;
    setFec(enabled: boolean): void;
    setMaxBandwidth(bandwidth: Bandwidth): void;
    setPacketLossPercent(percentage: number): void;
    setSignal(signal: Signal): void;
    setUseSmpl(enabled: boolean): void;
    setVbr(enabled: boolean): void;
    setVbrConstraint(enabled: boolean): void;
    [Symbol.dispose](): void;
};
export type OpusDecoderHandle = {
    readonly channels: ChannelCount;
    readonly maxFrameSize: number;
    readonly sampleRate: SampleRate;
    decode(packet: Uint8Array | null, options?: DecodeOptions): Int16Array;
    decodeFloat(packet: Uint8Array | null, options?: DecodeOptions): Float32Array;
    decodeFrames(packets: readonly (Uint8Array | null)[], options?: DecodeOptions): Int16Array[];
    decodeFloatFrames(packets: readonly (Uint8Array | null)[], options?: DecodeOptions): Float32Array[];
    decodePacketLoss(frameSize?: number): Int16Array;
    decodePacketLossFloat(frameSize?: number): Float32Array;
    decoderCtl(request: number, value: number): void;
    free(): void;
    setUseSmpl(enabled: boolean): void;
    [Symbol.dispose](): void;
};
export declare function opusGlobalCreate(): Promise<void>;
export declare function opusGlobalFree(): Promise<void>;
export declare function loadLibopus(): Promise<{
    version: string;
}>;
export declare function createEncoder(options?: EncoderOptions): Promise<OpusEncoderHandle>;
export declare function createDecoder(options?: DecoderOptions): Promise<OpusDecoderHandle>;
export declare function getPacketInfo(packet: Uint8Array, options?: PacketInfoOptions): Promise<OpusPacketInfo>;
export declare function getMlowPacketInfo(packet: Uint8Array, options?: PacketInfoOptions): Promise<MlowPacketInfo>;
export declare class OpusError extends Error {
    readonly code: number;
    readonly codeName: OpusErrorCodeName | undefined;
    readonly operation: string | undefined;
    constructor(code: number, message: string, operation?: string);
}
export declare const OpusErrorCode: {
    readonly BadArg: -1;
    readonly BufferTooSmall: -2;
    readonly InternalError: -3;
    readonly InvalidPacket: -4;
    readonly Unimplemented: -5;
    readonly InvalidState: -6;
    readonly AllocFail: -7;
};
export type OpusErrorCodeName = keyof typeof OpusErrorCode;
export declare function isOpusError(error: unknown): error is OpusError;
//# sourceMappingURL=index.d.ts.map