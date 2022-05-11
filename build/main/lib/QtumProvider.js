"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.compareVersion = exports.QtumProviderSubprovider = exports.QtumWebSocketProvider = exports.QtumJsonRpcProvider = exports.QtumProvider = void 0;
const ethers_1 = require("ethers");
const utils_1 = require("./helpers/utils");
const logger_1 = require("@ethersproject/logger");
const logger = new logger_1.Logger("qtum-ethers");
const properties_1 = require("@ethersproject/properties");
class QtumProvider extends QtumProviderMixin(ethers_1.providers.JsonRpcProvider) {
}
exports.QtumProvider = QtumProvider;
;
class QtumJsonRpcProvider extends QtumProviderMixin(ethers_1.providers.JsonRpcProvider) {
}
exports.QtumJsonRpcProvider = QtumJsonRpcProvider;
;
class QtumWebSocketProvider extends QtumProviderMixin(ethers_1.providers.WebSocketProvider) {
}
exports.QtumWebSocketProvider = QtumWebSocketProvider;
;
function timer(timeout) {
    return new Promise(function (resolve) {
        setTimeout(resolve, timeout);
    });
}
class ProviderSubprovider extends ethers_1.providers.BaseProvider {
    constructor(providerSubprovider, network) {
        if (!providerSubprovider) {
            throw new Error("Provider cannot be empty");
        }
        let networkOrReady = network;
        // The network is unknown, query the JSON-RPC for it
        if (networkOrReady == null) {
            networkOrReady = new Promise((resolve, reject) => {
                setTimeout(() => {
                    this.detectNetwork().then((network) => {
                        resolve(network);
                    }, (error) => {
                        reject(error);
                    });
                }, 0);
            });
        }
        super(networkOrReady);
        this._eventLoopCache = {};
        this.providerSubprovider = providerSubprovider;
    }
    get _cache() {
        if (this._eventLoopCache == null) {
            this._eventLoopCache = {};
        }
        return this._eventLoopCache;
    }
    send(method, params) {
        return new Promise((resolve, reject) => {
            this.providerSubprovider.handleRequest({
                method,
                params,
            }, undefined, (err, response) => {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(response);
                }
            });
        });
    }
    detectNetwork() {
        if (!this._cache["detectNetwork"]) {
            this._cache["detectNetwork"] = this._uncachedDetectNetwork();
            // Clear this cache at the beginning of the next event loop
            setTimeout(() => {
                this._cache["detectNetwork"] = null;
            }, 0);
        }
        return this._cache["detectNetwork"];
    }
    async _uncachedDetectNetwork() {
        await timer(0);
        let chainId = null;
        try {
            chainId = await this.send("eth_chainId", []);
        }
        catch (error) {
            try {
                chainId = await this.send("net_version", []);
            }
            catch (error) { }
        }
        if (chainId != null) {
            const getNetwork = properties_1.getStatic(this.constructor, "getNetwork");
            try {
                return getNetwork(BigNumber.from(chainId).toNumber());
            }
            catch (error) {
                return logger.throwError("could not detect network", logger_1.Logger.errors.NETWORK_ERROR, {
                    chainId: chainId,
                    event: "invalidNetwork",
                    serverError: error
                });
            }
        }
        return logger.throwError("could not detect network", logger_1.Logger.errors.NETWORK_ERROR, {
            event: "noNetwork"
        });
    }
}
class QtumProviderSubprovider extends QtumProviderMixin(ProviderSubprovider) {
}
exports.QtumProviderSubprovider = QtumProviderSubprovider;
;
function QtumProviderMixin(Base) {
    return class QtumProviderMixin extends Base {
        // EIP-1193 deprecated api support
        sendAsync(payload, cb) {
            // @ts-ignore
            this.send(payload.method, payload.params || []).then((result) => {
                cb(null, result);
            }).catch((err) => {
                cb(err);
            });
        }
        handleRequest(payload, _, end) {
            this.sendAsync(payload, end);
        }
        // EIP-1193
        request(payload) {
            // @ts-ignore
            return this.send(payload.method, payload.params || []);
        }
        /**
         * Override for QTUM parsing of transaction
         * https://github.com/ethers-io/ethers.js/blob/master/packages/providers/src.ts/base-provider.ts
         */
        async sendTransaction(signedTransaction) {
            // @ts-ignore
            await this.getNetwork();
            const signedTx = await Promise.resolve(signedTransaction);
            const hexTx = `0x${signedTx}`;
            // Parse the signed transaction here
            const tx = utils_1.parseSignedTransaction(signedTx);
            try {
                // @ts-ignore
                const hash = await this.perform("sendTransaction", {
                    signedTransaction: hexTx,
                });
                // Note: need to destructure return result here.
                // @ts-ignore
                return this._wrapTransaction(tx, hash);
            }
            catch (error) {
                error.transaction = tx;
                error.transactionHash = tx.hash;
                throw error;
            }
        }
        async isClientVersionGreaterThanEqualTo(major, minor, patch) {
            const ver = await this.getClientVersion();
            return compareVersion(ver, major, minor, patch) >= 0;
        }
        async getClientVersion() {
            // @ts-ignore
            await this.getNetwork();
            // @ts-ignore
            const version = await this.perform("web3_clientVersion", []);
            if (version === "QTUM ETHTestRPC/ethereum-js") {
                // 0.1.4, versions after this with a proper version string is 0.2.0
                // this version contains a bug we have to work around
                return {
                    name: "Janus",
                    version: "0.1.4",
                    major: 0,
                    minor: 1,
                    patch: 4,
                    system: "linux-amd64",
                };
            }
            else {
                const versionInfo = version.split("/");
                if (versionInfo.length >= 4) {
                    const semver = parseVersion(versionInfo[1]);
                    return {
                        name: versionInfo[0],
                        version: versionInfo[1],
                        major: semver[0] || 0,
                        minor: semver[1] || 0,
                        patch: semver[2] || 0,
                        system: versionInfo[2],
                    };
                }
            }
            return {
                name: version,
            };
        }
        /**
         * Function to handle grabbing UTXO's from janus
         * prepareRequest in https://github.com/ethers-io/ethers.js/blob/master/packages/providers/src.ts/json-rpc-provider.ts
         */
        async getUtxos(from, neededAmount) {
            // @ts-ignore
            await this.getNetwork();
            const params = !!!neededAmount ? [from, neededAmount, "p2pk", "p2pkh"] : [from, "p2pk", "p2pkh"];
            // @ts-ignore
            return await this.perform("qtum_qetUTXOs", params);
        }
        /**
         * Override to handle grabbing UTXO's from janus
         * prepareRequest in https://github.com/ethers-io/ethers.js/blob/master/packages/providers/src.ts/json-rpc-provider.ts
         */
        prepareRequest(method, params) {
            if (method === "qtum_qetUTXOs") {
                return ["qtum_getUTXOs", params];
            }
            else if (method === "web3_clientVersion") {
                return ["web3_clientVersion", params];
            }
            // @ts-ignore
            return super.prepareRequest(method, params);
        }
    };
}
function parseVersion(version) {
    const semver = version.split("-")[0];
    return semver.replace(/a-zA-Z\./g, "").split(".").map(i => parseInt(i) || 0);
}
function compareVersion(version, major, minor, patch) {
    return recursivelyCompareVersion([
        version.major || 0,
        version.minor || 0,
        version.patch || 0
    ], [
        major,
        minor,
        patch
    ]);
}
exports.compareVersion = compareVersion;
function recursivelyCompareVersion(version, compareTo) {
    if (version.length === 0) {
        return 0;
    }
    if (version[0] === compareTo[0]) {
        return recursivelyCompareVersion(version.slice(1), compareTo.slice(1));
    }
    else if (version[0] < compareTo[0]) {
        return -1;
    }
    else {
        return 1;
    }
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiUXR1bVByb3ZpZGVyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL2xpYi9RdHVtUHJvdmlkZXIudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUEsbUNBQW1DO0FBQ25DLDJDQUF5RDtBQUV6RCxrREFBK0M7QUFDL0MsTUFBTSxNQUFNLEdBQUcsSUFBSSxlQUFNLENBQUMsYUFBYSxDQUFDLENBQUM7QUFDekMsMERBQXNEO0FBc0J0RCxNQUFhLFlBQWEsU0FBUSxpQkFBaUIsQ0FBQyxrQkFBUyxDQUFDLGVBQWUsQ0FBQztDQUFHO0FBQWpGLG9DQUFpRjtBQUFBLENBQUM7QUFDbEYsTUFBYSxtQkFBb0IsU0FBUSxpQkFBaUIsQ0FBQyxrQkFBUyxDQUFDLGVBQWUsQ0FBQztDQUFHO0FBQXhGLGtEQUF3RjtBQUFBLENBQUM7QUFDekYsTUFBYSxxQkFBc0IsU0FBUSxpQkFBaUIsQ0FBQyxrQkFBUyxDQUFDLGlCQUFpQixDQUFDO0NBQUc7QUFBNUYsc0RBQTRGO0FBQUEsQ0FBQztBQUU3RixTQUFTLEtBQUssQ0FBQyxPQUFlO0lBQzFCLE9BQU8sSUFBSSxPQUFPLENBQUMsVUFBUyxPQUFPO1FBQy9CLFVBQVUsQ0FBQyxPQUFPLEVBQUUsT0FBTyxDQUFDLENBQUM7SUFDakMsQ0FBQyxDQUFDLENBQUM7QUFDUCxDQUFDO0FBTUQsTUFBTSxtQkFBb0IsU0FBUSxrQkFBUyxDQUFDLFlBQVk7SUFVcEQsWUFBWSxtQkFBa0MsRUFBRSxPQUFvQjtRQUNoRSxJQUFJLENBQUMsbUJBQW1CLEVBQUU7WUFDdEIsTUFBTSxJQUFJLEtBQUssQ0FBQywwQkFBMEIsQ0FBQyxDQUFDO1NBQy9DO1FBRUQsSUFBSSxjQUFjLEdBQThDLE9BQU8sQ0FBQztRQUV4RSxvREFBb0Q7UUFDcEQsSUFBSSxjQUFjLElBQUksSUFBSSxFQUFFO1lBQ3hCLGNBQWMsR0FBRyxJQUFJLE9BQU8sQ0FBQyxDQUFDLE9BQU8sRUFBRSxNQUFNLEVBQUUsRUFBRTtnQkFD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