import { resolveProperties, Logger, } from "ethers/lib/utils";
import { BigNumber } from "bignumber.js";
import { BigNumber as BigNumberEthers /*, providers*/ } from "ethers";
import { configureQtumAddressGeneration, checkTransactionType, serializeTransaction } from './helpers/utils';
import { GLOBAL_VARS } from './helpers/global-vars';
import { IntermediateWallet } from './helpers/IntermediateWallet';
import { decryptJsonWallet, decryptJsonWalletSync } from "@ethersproject/json-wallets";
import { HDNode, entropyToMnemonic } from "@ethersproject/hdnode";
import { arrayify, concat, hexDataSlice } from "@ethersproject/bytes";
import { randomBytes } from "@ethersproject/random";
import { keccak256 } from "@ethersproject/keccak256";
const logger = new Logger("QtumWallet");
const forwardErrors = [
    Logger.errors.INSUFFICIENT_FUNDS
];
const minimumGasPriceInGwei = "0x9502f9000";
const minimumGasPriceInWei = "0x5d21dba000";
// Qtum core wallet and electrum use coin 88
export const QTUM_BIP44_PATH = "m/44'/88'/0'/0/0";
// Other wallets use coin 2301
// for more details, see: https://github.com/satoshilabs/slips/pull/196
export const SLIP_BIP44_PATH = "m/44'/2301'/0'/0/0";
export const defaultPath = SLIP_BIP44_PATH;
const minimumGasPrice = "0x9502f9000";
export class QtumWallet extends IntermediateWallet {
    constructor(privateKey, provider, opts) {
        if (provider && provider.filterDust) {
            opts = provider;
            provider = undefined;
        }
        if (provider && !provider.getUtxos) {
            // throw new Error("QtumWallet provider requires getUtxos method: see QtumProvider")
        }
        super(privateKey, provider);
        this.qtumProvider = provider;
        this.opts = opts || {};
    }
    async serializeTransaction(utxos, neededAmount, tx, transactionType) {
        return await serializeTransaction(utxos, 
        // @ts-ignore
        (amount) => this.provider.getUtxos(tx.from, amount), neededAmount, tx, transactionType, this.privateKey, this.compressedPublicKey, this.opts.filterDust || false);
    }
    /**
     * Override to build a raw QTUM transaction signing UTXO's
     */
    async signTransaction(transaction) {
        let gasBugFixed = true;
        if (!this.provider) {
            throw new Error("No provider set, cannot sign transaction");
        }
        // @ts-ignore
        if (this.provider.isClientVersionGreaterThanEqualTo) {
            // @ts-ignore
            gasBugFixed = await this.provider.isClientVersionGreaterThanEqualTo(0, 2, 0);
        }
        else {
            throw new Error("Must use QtumProvider");
        }
        const augustFirst2022 = 1659330000000;
        const mayThirtith2022 = 1653886800000;
        const now = new Date().getTime();
        const requireFixedJanus = now > augustFirst2022;
        const message = "You are using an outdated version of Janus that has a bug that qtum-ethers-wrapper works around, " +
            "please upgrade your Janus instance and if you have hardcoded gas price in your dapp to update it to " +
            minimumGasPriceInWei + " - if you use eth_gasPrice then nothing else should be required other than updating Janus. " +
            "this message will become an error August 1st 2022 when using Janus instances lower than version 0.2.0";
        if (!gasBugFixed) {
            if (requireFixedJanus) {
                throw new Error(message);
            }
            else if (now > mayThirtith2022) {
                logger.warn(message);
            }
        }
        if (!transaction.gasPrice) {
            let gasPrice = minimumGasPriceInWei;
            if (!gasBugFixed) {
                gasPrice = minimumGasPriceInGwei;
            }
            // 40 satoshi in WEI
            // 40 => 40000000000
            // transaction.gasPrice = "0x9502f9000";
            // 40 => 400000000000
            // transaction.gasPrice = "0x5d21dba000";
            transaction.gasPrice = gasPrice;
        }
        else if (gasBugFixed) {
            if (requireFixedJanus) {
                // no work arounds after aug 1st 2022, worst case: this just means increased gas prices (10x) and shouldn't cause any other issues
                if (transaction.gasPrice === minimumGasPriceInGwei) {
                    // hardcoded 400 gwei gas price
                    // adjust it to be the proper amount and log an error
                    transaction.gasPrice = minimumGasPriceInWei;
                }
            }
        }
        const inSatoshi = BigNumberEthers.from(transaction.gasPrice).lt(BigNumberEthers.from('100000'));
        if (!inSatoshi && BigNumberEthers.from(transaction.gasPrice).lt(BigNumberEthers.from(minimumGasPrice))) {
            throw new Error("Gas price is too low (" + transaction.gasPrice + " - " + BigNumberEthers.from(transaction.gasPrice).toString() +
                "), it needs to be greater than " + minimumGasPrice +
                " (" + BigNumberEthers.from(minimumGasPrice).toString() + ") wei");
        }
        const gasPriceExponent = inSatoshi ? 'e-0' : (gasBugFixed ? 'e-10' : 'e-9');
        // convert gasPrice into satoshi
        let gasPrice = new BigNumber(BigNumberEthers.from(transaction.gasPrice).toString() + gasPriceExponent);
        transaction.gasPrice = gasPrice.toNumber();
        const tx = await resolveProperties(transaction);
        // Refactored to check TX type (call, create, p2pkh, deploy error) and calculate needed amount
        const { transactionType, neededAmount } = checkTransactionType(tx);
        // Check if the transactionType matches the DEPLOY_ERROR, throw error else continue
        if (transactionType === GLOBAL_VARS.DEPLOY_ERROR) {
            return logger.throwError("You cannot send QTUM while deploying a contract. Try deploying again without a value.", Logger.errors.NOT_IMPLEMENTED, {
                error: "You cannot send QTUM while deploying a contract. Try deploying again without a value.",
            });
        }
        let utxos = [];
        try {
            utxos = await this.getUtxos(tx.from, neededAmount, ["p2pk", "p2pkh"]);
        }
        catch (error) {
            if (forwardErrors.indexOf(error.code) >= 0) {
                throw error;
            }
            return logger.throwError("Needed amount of UTXO's exceed the total you own.", Logger.errors.INSUFFICIENT_FUNDS, {
                error: error,
            });
        }
        return await this.serializeTransaction(utxos, neededAmount, tx, transactionType);
    }
    async getUtxos(from, neededAmount, types = ["p2pk", "p2pkh"]) {
        const params = [from, neededAmount, ...types];
        if (!this.qtumProvider) {
            throw new Error("No provider defined");
        }
        const result = await this.do("qtum_qetUTXOs", params);
        if (result) {
            if (result instanceof Array) {
                return result;
            }
            else {
                return [result];
            }
        }
        return [];
    }
    do(payload, params) {
        // @ts-ignore
        if (this.provider.prepareRequest) {
            // @ts-ignore
            const args = this.provider.prepareRequest(payload, params);
            if (args) {
                payload = {
                    method: args[0],
                    params: args[1],
                };
                params = args[1];
            }
        }
        // @ts-ignore
        if (this.provider?.request) {
            // @ts-ignore
            return this.provider.request(payload, { params });
        }
        const next = (method) => {
            return new Promise((resolve, reject) => {
                // @ts-ignore
                this.provider[method]({
                    method: payload.method,
                    params: payload.params,
                }, undefined, (err, result) => {
                    if (err) {
                        reject(err);
                    }
                    else {
                        resolve(result);
                    }
                });
            });
        };
        // @ts-ignore
        if (this.provider?.handleRequest) {
            return next('handleRequest');
            // @ts-ignore
        }
        else if (this.provider?.sendAsync) {
            return next('sendAsync');
        }
        return Promise.reject(new Error("Unsupported provider"));
    }
    getPrivateKey() {
        return Buffer.from(this.privateKey);
    }
    getPrivateKeyString() {
        return this.privateKey;
    }
    getPublicKey() {
        return Buffer.from(this.publicKey);
    }
    getPublicKeyString() {
        return this.publicKey;
    }
    getAddressBuffer() {
        return Buffer.from(this.getAddressString());
    }
    getAddressString() {
        return (this.address || '').toLowerCase();
    }
    getChecksumAddressString() {
        return this.address;
    }
    static fromPrivateKey(privateKey) {
        return new QtumWallet(privateKey);
    }
    /**
     *  Static methods to create Wallet instances.
     */
    static createRandom(options) {
        let entropy = randomBytes(16);
        if (!options) {
            options = {};
        }
        if (options.extraEntropy) {
            entropy = arrayify(hexDataSlice(keccak256(concat([entropy, options.extraEntropy])), 0, 16));
        }
        const mnemonic = entropyToMnemonic(entropy, options.locale);
        return QtumWallet.fromMnemonic(mnemonic, options.path, options.locale);
    }
    static fromEncryptedJson(json, password, progressCallback) {
        return decryptJsonWallet(json, password, progressCallback).then((account) => {
            return new QtumWallet(account);
        });
    }
    static fromEncryptedJsonSync(json, password) {
        return new QtumWallet(decryptJsonWalletSync(json, password));
    }
    /**
     * Create a QtumWallet from a BIP44 mnemonic
     * @param mnemonic
     * @param path QTUM uses two different derivation paths and recommends SLIP_BIP44_PATH for external wallets, core wallets use QTUM_BIP44_PATH
     * @param wordlist
     * @returns
     */
    static fromMnemonic(mnemonic, path, wordlist) {
        if (!path) {
            path = defaultPath;
        }
        const hdnode = HDNode.fromMnemonic(mnemonic, "", wordlist).derivePath(path);
        return new QtumWallet(configureQtumAddressGeneration(hdnode));
    }
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiUXR1bVdhbGxldC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9saWIvUXR1bVdhbGxldC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxPQUFPLEVBQ0gsaUJBQWlCLEVBQ2pCLE1BQU0sR0FDVCxNQUFNLGtCQUFrQixDQUFDO0FBRTFCLE9BQU8sRUFBRSxTQUFTLEVBQUUsTUFBTSxjQUFjLENBQUE7QUFDeEMsT0FBTyxFQUFFLFNBQVMsSUFBSSxlQUFlLENBQUEsZUFBZSxFQUFFLE1BQU0sUUFBUSxDQUFDO0FBQ3JFLE9BQU8sRUFDSCw4QkFBOEIsRUFDOUIsb0JBQW9CLEVBQ3BCLG9CQUFvQixFQUN2QixNQUFNLGlCQUFpQixDQUFBO0FBQ3hCLE9BQU8sRUFBRSxXQUFXLEVBQUUsTUFBTSx1QkFBdUIsQ0FBQTtBQUNuRCxPQUFPLEVBQUUsa0JBQWtCLEVBQUUsTUFBTSw4QkFBOEIsQ0FBQTtBQUNqRSxPQUFPLEVBQUUsaUJBQWlCLEVBQUUscUJBQXFCLEVBQW9CLE1BQU0sNkJBQTZCLENBQUM7QUFDekcsT0FBTyxFQUFFLE1BQU0sRUFBRSxpQkFBaUIsRUFBRSxNQUFNLHVCQUF1QixDQUFDO0FBQ2xFLE9BQU8sRUFBRSxRQUFRLEVBQVMsTUFBTSxFQUFFLFlBQVksRUFBRSxNQUFNLHNCQUFzQixDQUFDO0FBQzdFLE9BQU8sRUFBRSxXQUFXLEVBQUUsTUFBTSx1QkFBdUIsQ0FBQztBQUNwRCxPQUFPLEVBQUUsU0FBUyxFQUFFLE1BQU0sMEJBQTBCLENBQUM7QUFJckQsTUFBTSxNQUFNLEdBQUcsSUFBSSxNQUFNLENBQUMsWUFBWSxDQUFDLENBQUM7QUFDeEMsTUFBTSxhQUFhLEdBQUc7SUFDbEIsTUFBTSxDQUFDLE1BQU0sQ0FBQyxrQkFBa0I7Q0FDbkMsQ0FBQztBQUVGLE1BQU0scUJBQXFCLEdBQUcsYUFBYSxDQUFDO0FBQzVDLE1BQU0sb0JBQW9CLEdBQUcsY0FBYyxDQUFDO0FBRTVDLDRDQUE0QztBQUM1QyxN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