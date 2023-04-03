"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyTypedData = exports.recoverAddress = exports.verifyHash = exports.verifyMessage = exports.IntermediateWallet = exports.hashMessage = exports.messagePrefix = exports.version = void 0;
// @ts-nocheck
const address_1 = require("@ethersproject/address");
const abstract_provider_1 = require("@ethersproject/abstract-provider");
const abstract_signer_1 = require("@ethersproject/abstract-signer");
const bytes_1 = require("@ethersproject/bytes");
const hash_1 = require("@ethersproject/hash");
const strings_1 = require("@ethersproject/strings");
const hdnode_1 = require("@ethersproject/hdnode");
const keccak256_1 = require("@ethersproject/keccak256");
const properties_1 = require("@ethersproject/properties");
const random_1 = require("@ethersproject/random");
const signing_key_1 = require("@ethersproject/signing-key");
const json_wallets_1 = require("@ethersproject/json-wallets");
const transactions_1 = require("@ethersproject/transactions");
const utils_1 = require("./utils");
const logger_1 = require("@ethersproject/logger");
const secp256k1_1 = __importDefault(require("secp256k1"));
const wif_1 = __importDefault(require("wif"));
exports.version = "wallet/5.1.0";
const logger = new logger_1.Logger(exports.version);
const allowedTransactionKeys = [
    "accessList", "chainId", "data", "from", "gasLimit", "gasPrice", "nonce", "to", "type", "value", "inputs"
];
exports.messagePrefix = "\x15Qtum Signed Message:\n";
function hashMessage(message) {
    if (typeof (message) === "string") {
        message = strings_1.toUtf8Bytes(message);
    }
    return keccak256_1.keccak256(bytes_1.concat([
        strings_1.toUtf8Bytes(exports.messagePrefix),
        strings_1.toUtf8Bytes(String(message.length)),
        message
    ]));
}
exports.hashMessage = hashMessage;
function encodeSignatureRSV(signature, recovery, compressed, segwitType) {
    /*
    if (segwitType !== undefined) {
      recovery += 8
      if (segwitType === SEGWIT_TYPES.P2WPKH) recovery += 4
    } else {
        */
    if (compressed)
        recovery += 4;
    // }
    // return Buffer.concat([Buffer.alloc(1, recovery + 27), signature])
    return Buffer.concat([signature, Buffer.alloc(1, recovery + 27)]);
}
function isAccount(value) {
    return (value != null && bytes_1.isHexString(value.privateKey, 32) && value.address != null);
}
function hasMnemonic(value) {
    const mnemonic = value.mnemonic;
    return (mnemonic && mnemonic.phrase);
}
// Created this class due to address being read only and unwriteable from derived classes.
class IntermediateWallet extends abstract_signer_1.Signer {
    constructor(privateKey, provider) {
        super();
        if (isAccount(privateKey)) {
            const signingKey = new signing_key_1.SigningKey(privateKey.privateKey);
            properties_1.defineReadOnly(this, "_signingKey", () => signingKey);
            properties_1.defineReadOnly(this, "address", utils_1.computeAddress(this.publicKey, true));
            if (address_1.getAddress(this.address) !== address_1.getAddress(privateKey.qtumAddress || privateKey.address)) {
                if (address_1.getAddress(transactions_1.computeAddress(this.publicKey)) === address_1.getAddress(privateKey.qtumAddress || privateKey.address)) {
                    logger.throwArgumentError("privateKey/address mismatch: Your address is being generated the ethereum way, please use QTUM address generation scheme", "privateKey", "[REDACTED]");
                }
                else {
                    logger.throwArgumentError("privateKey/address mismatch", "privateKey", "[REDACTED]");
                }
            }
            if (hasMnemonic(privateKey)) {
                const srcMnemonic = privateKey.mnemonic;
                properties_1.defineReadOnly(this, "_mnemonic", () => ({
                    phrase: srcMnemonic.phrase,
                    path: srcMnemonic.path || hdnode_1.defaultPath,
                    locale: srcMnemonic.locale || "en"
                }));
                const mnemonic = this.mnemonic;
                const node = hdnode_1.HDNode.fromMnemonic(mnemonic.phrase, null, mnemonic.locale).derivePath(mnemonic.path);
                if (utils_1.computeAddress(node.privateKey, true) !== this.address) {
                    logger.throwArgumentError("mnemonic/address mismatch", "privateKey", "[REDACTED]");
                }
            }
            else {
                properties_1.defineReadOnly(this, "_mnemonic", () => null);
            }
        }
        else {
            if (signing_key_1.SigningKey.isSigningKey(privateKey)) {
                /* istanbul ignore if */
                if (privateKey.curve !== "secp256k1") {
                    logger.throwArgumentError("unsupported curve; must be secp256k1", "privateKey", "[REDACTED]");
                }
                properties_1.defineReadOnly(this, "_signingKey", () => privateKey);
            }
            else {
                // A lot of common tools do not prefix private keys with a 0x (see: #1166)
                if (typeof (privateKey) === "string") {
                    if (privateKey.match(/^[0-9a-f]*$/i) && privateKey.length === 64) {
                        privateKey = "0x" + privateKey;
                    }
                }
                try {
                    if (!privateKey.startsWith("0x")) {
                        let decodedKey = wif_1.default.decode(privateKey);
                        privateKey = '0x' + decodedKey.privateKey.toString("hex");
                    }
                }
                catch (e) {
                    // not WIF format
                }
                const signingKey = new signing_key_1.SigningKey(privateKey);
                properties_1.defineReadOnly(this, "_signingKey", () => signingKey);
            }
            properties_1.defineReadOnly(this, "_mnemonic", () => null);
            properties_1.defineReadOnly(this, "address", utils_1.computeAddressFromPublicKey(this.compressedPublicKey));
        }
        /* istanbul ignore if */
        if (provider && !abstract_provider_1.Provider.isProvider(provider)) {
            logger.throwArgumentError("invalid provider", "provider", provider);
        }
        properties_1.defineReadOnly(this, "provider", provider || null);
    }
    get mnemonic() { return this._mnemonic(); }
    get privateKey() { return this._signingKey().privateKey; }
    get publicKey() { return this._signingKey().publicKey; }
    get compressedPublicKey() { return this._signingKey().compressedPublicKey; }
    getAddress() {
        return Promise.resolve(this.address);
    }
    connect(provider) {
        return new this.__proto__.constructor(this, provider);
    }
    checkTransaction(transaction) {
        for (const key in transaction) {
            if (allowedTransactionKeys.indexOf(key) === -1) {
                logger.throwArgumentError("invalid transaction key: " + key, "transaction", transaction);
            }
        }
        const tx = properties_1.shallowCopy(transaction);
        if (tx.from == null) {
            tx.from = this.getAddress();
        }
        else {
            // Make sure any provided address matches this signer
            tx.from = Promise.all([
                Promise.resolve(tx.from),
                this.getAddress()
            ]).then((result) => {
                if (result[0].toLowerCase() !== result[1].toLowerCase()) {
                    logger.throwArgumentError("from address mismatch", "transaction", transaction);
                }
                return result[0];
            });
        }
        return tx;
    }
    signTransaction(transaction) {
        return properties_1.resolveProperties(transaction).then((tx) => {
            if (tx.from != null) {
                if (address_1.getAddress(tx.from) !== this.address) {
                    logger.throwArgumentError("transaction from address mismatch", "transaction.from", transaction.from);
                }
                delete tx.from;
            }
            const signature = this._signingKey().signDigest(keccak256_1.keccak256(transactions_1.serialize(tx)));
            return transactions_1.serialize(tx, signature);
        });
    }
    async signMessage(message) {
        const digest = hashMessage(message);
        return await this.signHash(bytes_1.arrayify(digest));
    }
    async signHash(message) {
        if (typeof (message) === "string") {
            message = strings_1.toUtf8Bytes(message);
        }
        const sigObj = secp256k1_1.default.ecdsaSign(message, Buffer.from(this.privateKey.slice(2), "hex"));
        return encodeSignatureRSV(sigObj.signature, sigObj.recid, true);
    }
    async _signTypedData(domain, types, value) {
        // Populate any ENS names
        const populated = await hash_1._TypedDataEncoder.resolveNames(domain, types, value, (name) => {
            if (this.provider == null) {
                logger.throwError("cannot resolve ENS names without a provider", logger_1.Logger.errors.UNSUPPORTED_OPERATION, {
                    operation: "resolveName",
                    value: name
                });
            }
            return this.provider.resolveName(name);
        });
        return await this.signHash(hash_1._TypedDataEncoder.hash(populated.domain, types, populated.value));
    }
    sendTransactionIdempotent(transaction) {
        this._checkProvider("sendTransaction");
        return this.populateTransaction(transaction).then((tx) => {
            return this.signTransaction(tx).then((signedTx) => {
                const nonce = this.getIdempotentNonce(signedTx);
                tx.nonce = nonce.nonce;
                // @ts-ignore 
                tx.inputs = nonce.inputs;
                return {
                    nonce: nonce.nonce,
                    inputs: nonce.inputs,
                    transaction: tx,
                    signedTransaction: signedTx,
                    sendTransaction: () => this.provider.sendTransaction(signedTx),
                };
            });
        });
    }
    encrypt(password, options, progressCallback) {
        if (typeof (options) === "function" && !progressCallback) {
            progressCallback = options;
            options = {};
        }
        if (progressCallback && typeof (progressCallback) !== "function") {
            throw new Error("invalid callback");
        }
        if (!options) {
            options = {};
        }
        return json_wallets_1.encryptKeystore(this, password, options, progressCallback);
    }
    /**
     *  Static methods to create Wallet instances.
     */
    static createRandom(options) {
        let entropy = random_1.randomBytes(16);
        if (!options) {
            options = {};
        }
        if (options.extraEntropy) {
            entropy = bytes_1.arrayify(bytes_1.hexDataSlice(keccak256_1.keccak256(bytes_1.concat([entropy, options.extraEntropy])), 0, 16));
        }
        const mnemonic = hdnode_1.entropyToMnemonic(entropy, options.locale);
        return IntermediateWallet.fromMnemonic(mnemonic, options.path, options.locale);
    }
    static fromEncryptedJson(json, password, progressCallback) {
        return json_wallets_1.decryptJsonWallet(json, password, progressCallback).then((account) => {
            return new IntermediateWallet(account);
        });
    }
    static fromEncryptedJsonSync(json, password) {
        return new IntermediateWallet(json_wallets_1.decryptJsonWalletSync(json, password));
    }
    static fromMnemonic(mnemonic, path, wordlist) {
        if (!path) {
            path = hdnode_1.defaultPath;
        }
        return new IntermediateWallet(hdnode_1.HDNode.fromMnemonic(mnemonic, null, wordlist).derivePath(path));
    }
}
exports.IntermediateWallet = IntermediateWallet;
function verifyMessage(message, signature) {
    return recoverAddress(hashMessage(message), signature);
}
exports.verifyMessage = verifyMessage;
function verifyHash(message, signature) {
    return recoverAddress(message, signature);
}
exports.verifyHash = verifyHash;
function recoverAddress(digest, signature) {
    return utils_1.computeAddress(recoverPublicKey(bytes_1.arrayify(digest), signature));
}
exports.recoverAddress = recoverAddress;
function verifyTypedData(domain, types, value, signature) {
    return recoverAddress(hash_1._TypedDataEncoder.hash(domain, types, value), signature);
}
exports.verifyTypedData = verifyTypedData;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiSW50ZXJtZWRpYXRlV2FsbGV0LmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vLi4vc3JjL2xpYi9oZWxwZXJzL0ludGVybWVkaWF0ZVdhbGxldC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7QUFBQSxjQUFjO0FBQ2Qsb0RBQW9EO0FBQ3BELHdFQUFxRztBQUNyRyxvRUFBa0k7QUFDbEksZ0RBQW1JO0FBQ25JLDhDQUF3RDtBQUN4RCxvREFBcUQ7QUFDckQsa0RBQXlGO0FBQ3pGLHdEQUFxRDtBQUNyRCwwREFBdUc7QUFDdkcsa0RBQW9EO0FBQ3BELDREQUF3RDtBQUN4RCw4REFBMEg7QUFDMUgsOERBS3FDO0FBRXJDLG1DQUFvRTtBQUNwRSxrREFBK0M7QUFDL0MsMERBQWtDO0FBQ2xDLDhDQUFzQjtBQUlULFFBQUEsT0FBTyxHQUFHLGNBQWMsQ0FBQztBQUN0QyxNQUFNLE1BQU0sR0FBRyxJQUFJLGVBQU0sQ0FBQyxlQUFPLENBQUMsQ0FBQztBQUVuQyxNQUFNLHNCQUFzQixHQUFrQjtJQUMxQyxZQUFZLEVBQUUsU0FBUyxFQUFFLE1BQU0sRUFBRSxNQUFNLEVBQUUsVUFBVSxFQUFFLFVBQVUsRUFBRSxPQUFPLEVBQUUsSUFBSSxFQUFFLE1BQU0sRUFBRSxPQUFPLEVBQUUsUUFBUTtDQUM1RyxDQUFDO0FBSVcsUUFBQSxhQUFhLEdBQUcsNEJBQTRCLENBQUM7QUFFMUQsU0FBZ0IsV0FBVyxDQUFDLE9BQXVCO0lBQy9DLElBQUksT0FBTSxDQUFDLE9BQU8sQ0FBQyxLQUFLLFFBQVEsRUFBRTtRQUFFLE9BQU8sR0FBRyxxQkFBVyxDQUFDLE9BQU8sQ0FBQyxDQUFDO0tBQUU7SUFDckUsT0FBTyxxQkFBUyxDQUFDLGNBQU0sQ0FBQztRQUNwQixxQkFBVyxDQUFDLHFCQUFhLENBQUM7UUFDMUIscUJBQVcsQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxDQUFDO1FBQ25DLE9BQU87S0FDVixDQUFDLENBQUMs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