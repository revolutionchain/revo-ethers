import { HDNode } from '@ethersproject/hdnode';
import { configureRevoAddressGeneration } from './helpers/utils';
import { RevoWallet } from './RevoWallet';

export class RevoHDKey {
    private readonly _hdkey: HDNode;

    static fromMasterSeed(seedBuffer: Buffer): RevoHDKey {
        const hdnode = configureRevoAddressGeneration(HDNode.fromSeed("0x" + seedBuffer.toString('hex')));
        return new RevoHDKey(hdnode);
    }

    static fromExtendedKey(base58Key: string): RevoHDKey {
        const hdnode = configureRevoAddressGeneration(HDNode.fromExtendedKey("0x" + base58Key));
        return new RevoHDKey(hdnode);
    }

    constructor(hdkey: HDNode) {
        this._hdkey = hdkey;
        configureRevoAddressGeneration(hdkey);
    }

    privateExtendedKey(): Buffer {
        if (!this._hdkey.privateKey) {
            throw new Error('This is a public key only wallet');
        }
        return Buffer.from(this._hdkey.extendedKey);
    }

    publicExtendedKey(): Buffer {
        return Buffer.from(this._hdkey.neuter().extendedKey);
    }

    derivePath(path: string): RevoHDKey {
        return new RevoHDKey(
            configureRevoAddressGeneration(HDNode.fromExtendedKey(this._hdkey.extendedKey).derivePath(path))
        );
    }

    deriveChild(index: number): RevoHDKey {
        return new RevoHDKey(
            // @ts-ignore
            configureRevoAddressGeneration(HDNode.fromExtendedKey(this._hdkey.extendedKey)._derive(index))
        );
    }

    getWallet(): RevoWallet {
        return new RevoWallet(configureRevoAddressGeneration(HDNode.fromExtendedKey(this._hdkey.extendedKey)));
    }
}