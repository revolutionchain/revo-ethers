import { utils, Wallet } from 'ethers';
import { BytesLike , Hexable } from '@ethersproject/bytes';
import { RevoProvider } from "./RevoProvider";
import { RevoWallet, REVO_BIP44_PATH } from "./RevoWallet";
import { parseSignedTransaction } from "./helpers/utils";

export interface RecordedCall {
    readonly address: string | undefined;
    readonly data: string;
}

export interface IProviderOptions {
    account_keys_path?: string;
    accounts?: object[];
    allowUnlimitedContractSize?: boolean;
    blockTime?: number;
    db_path?: string;
    debug?: boolean;
    default_balance_ether?: number;
    fork?: string | object;
    fork_block_number?: string | number;
    forkCacheSize?: number;
    gasLimit?: string | number;
    gasPrice?: string;
    hardfork?: "byzantium" | "constantinople" | "petersburg" | "istanbul" | "muirGlacier";
    hd_path?: string;
    locked?: boolean;
    logger?: {
      log(msg: string): void;
    };
    mnemonic?: string;
    network_id?: number;
    networkId?: number;
    url?: string;
    port?: number;
    seed?: any;
    time?: Date;
    total_accounts?: number;
    unlocked_accounts?: string[];
    verbose?: boolean;
    vmErrorsOnRPCResponse?: boolean;
    ws?: boolean;
}

export class RevoTestProvider extends RevoProvider {

    private wallets: Wallet[];
    private _callHistory: RecordedCall[];

    constructor(
        options?: IProviderOptions | undefined,
    ) {
        super(
            options ?
                ((options.url || "http://localhost:") + (options.port || 23889))
                    : "http://localhost:23889"
        );

        this.wallets = [];
        this._callHistory = [];

        options = options || {};
        if (!options.accounts || options.accounts.length === 0) {
            if (options.mnemonic) {
                this.wallets.push(
                    RevoWallet.fromMnemonic(
                        options.mnemonic,
                        options.hd_path || REVO_BIP44_PATH
                    ).connect(this)
                );
                for (let j = 1; j < 5; j++) {
                    this.wallets.push(
                        RevoWallet.fromMnemonic(
                            options.mnemonic,
                            (options.hd_path || REVO_BIP44_PATH) + "/" + j
                        ).connect(this)
                    );
                }
            } else {
                options.accounts = [
                    "cMbgxCJrTYUqgcmiC1berh5DFrtY1KeU4PXZ6NZxgenniF1mXCRk",
                    "cRcG1jizfBzHxfwu68aMjhy78CpnzD9gJYZ5ggDbzfYD3EQfGUDZ",
                    "cV79qBoCSA2NDrJz8S3T7J8f3zgkGfg4ua4hRRXfhbnq5VhXkukT",
                    "cV93kaaV8hvNqZ711s2z9jVWLYEtwwsVpyFeEZCP6otiZgrCTiEW",
                    "cVPHpTvmv3UjQsZfsMRrW5RrGCyTSAZ3MWs1f8R1VeKJSYxy5uac",
                    "cTs5NqY4Ko9o6FESHGBDEG77qqz9me7cyYCoinHcWEiqMZgLC6XY"
                ].map(privateKey => ({privateKey}));
            }
        }

        if (options.accounts && options.accounts.length !== 0) {
            for (let i = 0; i < options.accounts.length; i++) {
                // @ts-ignore
                this.wallets.push(new RevoWallet(options.accounts[i].privateKey).connect(this));
            }
        }
    }

    prepareRequest(method: any, params: any): [string, Array<any>] {
        switch (method) {
            case "sendTransaction":
                if (this._callHistory) {
                    if (params.hasOwnProperty("signedTransaction")) {
                        try {
                            const tx = parseSignedTransaction(params.signedTransaction);
                            if (tx.to) {
                                // OP_CALL
                                this._callHistory.push(toRecordedCall(tx.to, '0x' + tx.data));
                            }
                        } catch (e) {
                            // ignore
                            console.error("Failed to parse", params.signedTransaction, e)
                        }
                    }
                }
                break;
            case "call":
                if (this._callHistory) {
                    if (params.hasOwnProperty("transaction")) {
                        this._callHistory.push(toRecordedCall(params.transaction.to, params.transaction.data));
                    }
                }
                break;
        }
        if (method === "revo_qetUTXOs") {
            return ["revo_getUTXOs", params];
        }
        return super.prepareRequest(method, params);
    }

    public getWallets(): Wallet[] {
        return this.wallets;
    }

    public createEmptyWallet(): Wallet {
        return RevoWallet.createRandom().connect(this);
    }

    public clearCallHistory() {
        this._callHistory = [];
    }

    get callHistory() {
        return this._callHistory;
    }
}

function toRecordedCall(to?: BytesLike | Hexable | number, data?: BytesLike | Hexable | number) {
    return {
        address: to ? utils.getAddress(utils.hexlify(to)) : undefined,
        data: data ? utils.hexlify(data) : '0x'
    };
}
