/// <reference types="node" />
import { HDNode } from '@ethersproject/hdnode';
import { RevoWallet } from './RevoWallet';
export declare class RevoHDKey {
    private readonly _hdkey;
    static fromMasterSeed(seedBuffer: Buffer): RevoHDKey;
    static fromExtendedKey(base58Key: string): RevoHDKey;
    constructor(hdkey: HDNode);
    privateExtendedKey(): Buffer;
    publicExtendedKey(): Buffer;
    derivePath(path: string): RevoHDKey;
    deriveChild(index: number): RevoHDKey;
    getWallet(): RevoWallet;
}
