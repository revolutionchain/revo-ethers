// @ts-nocheck
const { RevoProvider } = require("../../build/main/lib/RevoProvider");

const provider = new RevoProvider("http://localhost:23890");

describe("RevoProvider", function () {
    it("can grab UTXOs for an address", async function () {
        await provider.getUtxos("0x7926223070547D2D15b2eF5e7383E541c338FfE9", "1.0");
    });
})