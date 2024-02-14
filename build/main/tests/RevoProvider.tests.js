"use strict";
// @ts-nocheck
const { RevoProvider } = require("../../build/main/lib/RevoProvider");
const provider = new RevoProvider("http://localhost:23890");
describe("RevoProvider", function () {
    it("can grab UTXOs for an address", async function () {
        await provider.getUtxos("0x7926223070547D2D15b2eF5e7383E541c338FfE9", "1.0");
    });
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiUmV2b1Byb3ZpZGVyLnRlc3RzLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL3Rlc3RzL1Jldm9Qcm92aWRlci50ZXN0cy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiO0FBQUEsY0FBYztBQUNkLE1BQU0sRUFBRSxZQUFZLEVBQUUsR0FBRyxPQUFPLENBQUMsbUNBQW1DLENBQUMsQ0FBQztBQUV0RSxNQUFNLFFBQVEsR0FBRyxJQUFJLFlBQVksQ0FBQyx3QkFBd0IsQ0FBQyxDQUFDO0FBRTVELFFBQVEsQ0FBQyxjQUFjLEVBQUU7SUFDckIsRUFBRSxDQUFDLCtCQUErQixFQUFFLEtBQUs7UUFDckMsTUFBTSxRQUFRLENBQUMsUUFBUSxDQUFDLDRDQUE0QyxFQUFFLEtBQUssQ0FBQyxDQUFDO0lBQ2pGLENBQUMsQ0FBQyxDQUFDO0FBQ1AsQ0FBQyxDQUFDLENBQUEifQ==