// const { keccak256 } = require("ethers/lib/utils");

// @ts-nocheck
const { expect } = require("chai");
const { QtumWallet } = require("../../build/main/lib/QtumWallet");
const { QtumProvider } = require("../../build/main/lib/QtumProvider");
const { recoverAddress, hashMessage, verifyMessage } = require("../../build/main/lib/helpers/utils");
const provider = new QtumProvider("http://localhost:23890");
const { arrayify } = require("@ethersproject/bytes");
const { keccak256 } = require("ethers/lib/utils");

// hash160PubKey/address -> 0xcdf409a70058bfc54ada1ee3422f1ef28d0d267d
const signer = new QtumWallet(
    "99dda7e1a59655c9e02de8592be3b914df7df320e72ce04ccf0427f9a366ec6e",
    provider
);

describe("Utils", function () {
    it("recoverAddress", async function () {
        const message = "1234";
        const digest = hashMessage(message);
        const address = await signer.getAddress();
        const signedMessage = await signer.signMessage(message);
        const recovered = recoverAddress(digest, signedMessage);
        expect(recovered).to.equal(address, "Recovered wrong address")
    });
    it("verifyMessage", async function () {
        const message = "1234";
        const address = await signer.getAddress();
        const signedMessage = await signer.signMessage(message);
        const recovered = verifyMessage(message, signedMessage);
        expect(recovered).to.equal(address, "Recovered wrong address")
    });
})
