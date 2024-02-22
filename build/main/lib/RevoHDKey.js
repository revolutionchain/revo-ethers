"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RevoHDKey = void 0;
const hdnode_1 = require("@ethersproject/hdnode");
const utils_1 = require("./helpers/utils");
const RevoWallet_1 = require("./RevoWallet");
class RevoHDKey {
    constructor(hdkey) {
        this._hdkey = hdkey;
        utils_1.configureRevoAddressGeneration(hdkey);
    }
    static fromMasterSeed(seedBuffer) {
        const hdnode = utils_1.configureRevoAddressGeneration(hdnode_1.HDNode.fromSeed("0x" + seedBuffer.toString('hex')));
        return new RevoHDKey(hdnode);
    }
    static fromExtendedKey(base58Key) {
        const hdnode = utils_1.configureRevoAddressGeneration(hdnode_1.HDNode.fromExtendedKey("0x" + base58Key));
        return new RevoHDKey(hdnode);
    }
    privateExtendedKey() {
        if (!this._hdkey.privateKey) {
            throw new Error('This is a public key only wallet');
        }
        return Buffer.from(this._hdkey.extendedKey);
    }
    publicExtendedKey() {
        return Buffer.from(this._hdkey.neuter().extendedKey);
    }
    derivePath(path) {
        return new RevoHDKey(utils_1.configureRevoAddressGeneration(hdnode_1.HDNode.fromExtendedKey(this._hdkey.extendedKey).derivePath(path)));
    }
    deriveChild(index) {
        return new RevoHDKey(
        // @ts-ignore
        utils_1.configureRevoAddressGeneration(hdnode_1.HDNode.fromExtendedKey(this._hdkey.extendedKey)._derive(index)));
    }
    getWallet() {
        return new RevoWallet_1.RevoWallet(utils_1.configureRevoAddressGeneration(hdnode_1.HDNode.fromExtendedKey(this._hdkey.extendedKey)));
    }
}
exports.RevoHDKey = RevoHDKey;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiUmV2b0hES2V5LmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL2xpYi9SZXZvSERLZXkudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUEsa0RBQStDO0FBQy9DLDJDQUFpRTtBQUNqRSw2Q0FBMEM7QUFFMUMsTUFBYSxTQUFTO0lBYWxCLFlBQVksS0FBYTtRQUNyQixJQUFJLENBQUMsTUFBTSxHQUFHLEtBQUssQ0FBQztRQUNwQixzQ0FBOEIsQ0FBQyxLQUFLLENBQUMsQ0FBQztJQUMxQyxDQUFDO0lBYkQsTUFBTSxDQUFDLGNBQWMsQ0FBQyxVQUFrQjtRQUNwQyxNQUFNLE1BQU0sR0FBRyxzQ0FBOEIsQ0FBQyxlQUFNLENBQUMsUUFBUSxDQUFDLElBQUksR0FBRyxVQUFVLENBQUMsUUFBUSxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsQ0FBQztRQUNsRyxPQUFPLElBQUksU0FBUyxDQUFDLE1BQU0sQ0FBQyxDQUFDO0lBQ2pDLENBQUM7SUFFRCxNQUFNLENBQUMsZUFBZSxDQUFDLFNBQWlCO1FBQ3BDLE1BQU0sTUFBTSxHQUFHLHNDQUE4QixDQUFDLGVBQU0sQ0FBQyxlQUFlLENBQUMsSUFBSSxHQUFHLFNBQVMsQ0FBQyxDQUFDLENBQUM7UUFDeEYsT0FBTyxJQUFJLFNBQVMsQ0FBQyxNQUFNLENBQUMsQ0FBQztJQUNqQyxDQUFDO0lBT0Qsa0JBQWtCO1FBQ2QsSUFBSSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsVUFBVSxFQUFFO1lBQ3pCLE1BQU0sSUFBSSxLQUFLLENBQUMsa0NBQWtDLENBQUMsQ0FBQztTQUN2RDtRQUNELE9BQU8sTUFBTSxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLFdBQVcsQ0FBQyxDQUFDO0lBQ2hELENBQUM7SUFFRCxpQkFBaUI7UUFDYixPQUFPLE1BQU0sQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxNQUFNLEVBQUUsQ0FBQyxXQUFXLENBQUMsQ0FBQztJQUN6RCxDQUFDO0lBRUQsVUFBVSxDQUFDLElBQVk7UUFDbkIsT0FBTyxJQUFJLFNBQVMsQ0FDaEIsc0NBQThCLENBQUMsZUFBTSxDQUFDLGVBQWUsQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLFdBQVcsQ0FBQyxDQUFDLFVBQVUsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUNuRyxDQUFDO0lBQ04sQ0FBQztJQUVELFdBQVcsQ0FBQyxLQUFhO1FBQ3JCLE9BQU8sSUFBSSxTQUFTO1FBQ2hCLGFBQWE7UUFDYixzQ0FBOEIsQ0FBQyxlQUFNLENBQUMsZUFBZSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsV0FBVyxDQUFDLENBQUMsT0FBTyxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQ2pHLENBQUM7SUFDTixDQUFDO0lBRUQsU0FBUztRQUNMLE9BQU8sSUFBSSx1QkFBVSxDQUFDLHNDQUE4QixDQUFDLGVBQU0sQ0FBQyxlQUFlLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxXQUFXLENBQUMsQ0FBQyxDQUFDLENBQUM7SUFDM0csQ0FBQztDQUNKO0FBN0NELDhCQTZDQyJ9