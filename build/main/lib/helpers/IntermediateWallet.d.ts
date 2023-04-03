import { Provider, TransactionRequest, TransactionResponse } from "@ethersproject/abstract-provider";
import { ExternallyOwnedAccount, Signer, TypedDataDomain, TypedDataField, TypedDataSigner } from "@ethersproject/abstract-signer";
import { Bytes, BytesLike, SignatureLike } from "@ethersproject/bytes";
import { Mnemonic } from "@ethersproject/hdnode";
import { Deferrable } from "@ethersproject/properties";
import { SigningKey } from "@ethersproject/signing-key";
import { ProgressCallback } from "@ethersproject/json-wallets";
import { Wordlist } from "@ethersproject/wordlists";
import { InputNonces } from "../QtumWallet";
import { Transaction } from "bitcoinjs-lib";
export declare const version = "wallet/5.1.0";
export declare const messagePrefix = "\u0015Qtum Signed Message:\n";
export declare function hashMessage(message: Bytes | string): string;
/**
 * Idempotency in Bitcoin forks requires spending the same Bitcoin inputs
 * As long as one of the inputs has already been spent, then the request will fail
 * This also means that sending multiple transactions in the same block requires
 * that you specify which inputs to avoid for subsequent transactions so that
 * you are not trying to double-spend the same inputs as the blockchain will
 * reject one of the requests and you won't necessarily know which one will
 * get rejected
 * (this is how you would overwrite a transaction in the mempool - by increasing the fee)
 */
export interface IdempotentRequest {
    nonce: string;
    inputs: Array<string>;
    transaction: QtumTransactionRequest;
    signedTransaction: string;
    sendTransaction: () => Promise<TransactionResponse>;
}
export interface InputNonces {
    nonce: string;
    inputs: Array<string>;
    decoded: Transaction;
}
export interface Idempotent {
    getIdempotentNonce(signedTransaction: string): InputNonces;
    sendTransactionIdempotent(transaction: Deferrable<QtumTransactionRequest>): Promise<IdempotentRequest>;
}
export declare type QtumTransactionRequest = TransactionRequest & {
    inputs?: Array<string>;
};
export declare class IntermediateWallet extends Signer implements ExternallyOwnedAccount, TypedDataSigner, Idempotent {
    readonly address: string;
    readonly provider: Provider;
    readonly _signingKey: () => SigningKey;
    readonly _mnemonic: () => Mnemonic;
    constructor(privateKey: BytesLike | ExternallyOwnedAccount | SigningKey, provider?: Provider);
    get mnemonic(): Mnemonic;
    get privateKey(): string;
    get publicKey(): string;
    get compressedPublicKey(): string;
    getAddress(): Promise<string>;
    connect<T extends typeof IntermediateWallet>(provider: Provider): InstanceType<T>;
    checkTransaction(transaction: Deferrable<TransactionRequest>): Deferrable<TransactionRequest>;
    signTransaction(transaction: QtumTransactionRequest): Promise<string>;
    signMessage(message: Bytes | string): Promise<string>;
    signHash(message: Bytes | string): Promise<string>;
    _signTypedData(domain: TypedDataDomain, types: Record<string, Array<TypedDataField>>, value: Record<string, any>): Promise<string>;
    abstract getIdempotentNonce(signedTransaction: string): InputNonces;
    sendTransactionIdempotent(transaction: Deferrable<QtumTransactionRequest>): Promise<IdempotentRequest>;
    encrypt(password: Bytes | string, options?: any, progressCallback?: ProgressCallback): Promise<string>;
    /**
     *  Static methods to create Wallet instances.
     */
    static createRandom(options?: any): IntermediateWallet;
    static fromEncryptedJson(json: string, password: Bytes | string, progressCallback?: ProgressCallback): Promise<IntermediateWallet>;
    static fromEncryptedJsonSync(json: string, password: Bytes | string): IntermediateWallet;
    static fromMnemonic(mnemonic: string, path?: string, wordlist?: Wordlist): IntermediateWallet;
}
export declare function verifyMessage(message: Bytes | string, signature: SignatureLike): string;
export declare function verifyHash(message: Bytes | string, signature: SignatureLike): string;
export declare function recoverAddress(digest: BytesLike, signature: SignatureLike): string;
export declare function verifyTypedData(domain: TypedDataDomain, types: Record<string, Array<TypedDataField>>, value: Record<string, any>, signature: SignatureLike): string;
