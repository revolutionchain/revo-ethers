import { providers } from "ethers";
import { parseSignedTransaction } from "./helpers/utils";
import { Logger } from "@ethersproject/logger";
const logger = new Logger("qtum-ethers");
import { getStatic } from "@ethersproject/properties";
export class QtumProvider extends QtumProviderMixin(providers.JsonRpcProvider) {
}
;
export class QtumJsonRpcProvider extends QtumProviderMixin(providers.JsonRpcProvider) {
}
;
export class QtumWebSocketProvider extends QtumProviderMixin(providers.WebSocketProvider) {
}
;
function timer(timeout) {
    return new Promise(function (resolve) {
        setTimeout(resolve, timeout);
    });
}
class ProviderSubprovider extends providers.BaseProvider {
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
            const getNetwork = getStatic(this.constructor, "getNetwork");
            try {
                return getNetwork(BigNumber.from(chainId).toNumber());
            }
            catch (error) {
                return logger.throwError("could not detect network", Logger.errors.NETWORK_ERROR, {
                    chainId: chainId,
                    event: "invalidNetwork",
                    serverError: error
                });
            }
        }
        return logger.throwError("could not detect network", Logger.errors.NETWORK_ERROR, {
            event: "noNetwork"
        });
    }
}
export class QtumProviderSubprovider extends QtumProviderMixin(ProviderSubprovider) {
}
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
            const tx = parseSignedTransaction(signedTx);
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
export function compareVersion(version, major, minor, patch) {
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiUXR1bVByb3ZpZGVyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL2xpYi9RdHVtUHJvdmlkZXIudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsT0FBTyxFQUFFLFNBQVMsRUFBRSxNQUFNLFFBQVEsQ0FBQztBQUNuQyxPQUFPLEVBQUUsc0JBQXNCLEVBQUUsTUFBTSxpQkFBaUIsQ0FBQztBQUV6RCxPQUFPLEVBQUUsTUFBTSxFQUFFLE1BQU0sdUJBQXVCLENBQUM7QUFDL0MsTUFBTSxNQUFNLEdBQUcsSUFBSSxNQUFNLENBQUMsYUFBYSxDQUFDLENBQUM7QUFDekMsT0FBTyxFQUFFLFNBQVMsRUFBRSxNQUFNLDJCQUEyQixDQUFDO0FBc0J0RCxNQUFNLE9BQU8sWUFBYSxTQUFRLGlCQUFpQixDQUFDLFNBQVMsQ0FBQyxlQUFlLENBQUM7Q0FBRztBQUFBLENBQUM7QUFDbEYsTUFBTSxPQUFPLG1CQUFvQixTQUFRLGlCQUFpQixDQUFDLFNBQVMsQ0FBQyxlQUFlLENBQUM7Q0FBRztBQUFBLENBQUM7QUFDekYsTUFBTSxPQUFPLHFCQUFzQixTQUFRLGlCQUFpQixDQUFDLFNBQVMsQ0FBQyxpQkFBaUIsQ0FBQztDQUFHO0FBQUEsQ0FBQztBQUU3RixTQUFTLEtBQUssQ0FBQyxPQUFlO0lBQzFCLE9BQU8sSUFBSSxPQUFPLENBQUMsVUFBUyxPQUFPO1FBQy9CLFVBQVUsQ0FBQyxPQUFPLEVBQUUsT0FBTyxDQUFDLENBQUM7SUFDakMsQ0FBQyxDQUFDLENBQUM7QUFDUCxDQUFDO0FBTUQsTUFBTSxtQkFBb0IsU0FBUSxTQUFTLENBQUMsWUFBWTtJQVVwRCxZQUFZLG1CQUFrQyxFQUFFLE9BQW9CO1FBQ2hFLElBQUksQ0FBQyxtQkFBbUIsRUFBRTtZQUN0QixNQUFNLElBQUksS0FBSyxDQUFDLDBCQUEwQixDQUFDLENBQUM7U0FDL0M7UUFFRCxJQUFJLGNBQWMsR0FBOEMsT0FBTyxDQUFDO1FBRXhFLG9EQUFvRDtRQUNwRCxJ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