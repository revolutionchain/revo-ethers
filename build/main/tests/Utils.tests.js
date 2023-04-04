"use strict";
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
const signer = new QtumWallet("99dda7e1a59655c9e02de8592be3b914df7df320e72ce04ccf0427f9a366ec6e", provider);
describe("Utils", function () {
    it("recoverAddress", async function () {
        const message = "1234";
        const digest = hashMessage(message);
        const address = await signer.getAddress();
        const signedMessage = await signer.signMessage(message);
        const recovered = recoverAddress(digest, signedMessage);
        expect(recovered).to.equal(address, "Recovered wrong address");
    });
    it.only("verifyMessage", async function () {
        const message = "1234";
        const address = await signer.getAddress();
        const signedMessage = await signer.signMessage(message);
        const recovered = verifyMessage(message, signedMessage);
        expect(recovered).to.equal(address, "Recovered wrong address");
    });
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiVXRpbHMudGVzdHMuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi9zcmMvdGVzdHMvVXRpbHMudGVzdHMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IjtBQUFBLHFEQUFxRDtBQUVyRCxjQUFjO0FBQ2QsTUFBTSxFQUFFLE1BQU0sRUFBRSxHQUFHLE9BQU8sQ0FBQyxNQUFNLENBQUMsQ0FBQztBQUNuQyxNQUFNLEVBQUUsVUFBVSxFQUFFLEdBQUcsT0FBTyxDQUFDLGlDQUFpQyxDQUFDLENBQUM7QUFDbEUsTUFBTSxFQUFFLFlBQVksRUFBRSxHQUFHLE9BQU8sQ0FBQyxtQ0FBbUMsQ0FBQyxDQUFDO0FBQ3RFLE1BQU0sRUFBRSxjQUFjLEVBQUUsV0FBVyxFQUFFLGFBQWEsRUFBRSxHQUFHLE9BQU8sQ0FBQyxvQ0FBb0MsQ0FBQyxDQUFDO0FBQ3JHLE1BQU0sUUFBUSxHQUFHLElBQUksWUFBWSxDQUFDLHdCQUF3QixDQUFDLENBQUM7QUFDNUQsTUFBTSxFQUFFLFFBQVEsRUFBRSxHQUFHLE9BQU8sQ0FBQyxzQkFBc0IsQ0FBQyxDQUFDO0FBQ3JELE1BQU0sRUFBRSxTQUFTLEVBQUUsR0FBRyxPQUFPLENBQUMsa0JBQWtCLENBQUMsQ0FBQztBQUVsRCxzRUFBc0U7QUFDdEUsTUFBTSxNQUFNLEdBQUcsSUFBSSxVQUFVLENBQ3pCLGtFQUFrRSxFQUNsRSxRQUFRLENBQ1gsQ0FBQztBQUVGLFFBQVEsQ0FBQyxPQUFPLEVBQUU7SUFDZCxFQUFFLENBQUMsZ0JBQWdCLEVBQUUsS0FBSztRQUN0QixNQUFNLE9BQU8sR0FBRyxNQUFNLENBQUM7UUFDdkIsTUFBTSxNQUFNLEdBQUcsV0FBVyxDQUFDLE9BQU8sQ0FBQyxDQUFDO1FBQ3BDLE1BQU0sT0FBTyxHQUFHLE1BQU0sTUFBTSxDQUFDLFVBQVUsRUFBRSxDQUFDO1FBQzFDLE1BQU0sYUFBYSxHQUFHLE1BQU0sTUFBTSxDQUFDLFdBQVcsQ0FBQyxPQUFPLENBQUMsQ0FBQztRQUN4RCxNQUFNLFNBQVMsR0FBRyxjQUFjLENBQUMsTUFBTSxFQUFFLGFBQWEsQ0FBQyxDQUFDO1FBQ3hELE1BQU0sQ0FBQyxTQUFTLENBQUMsQ0FBQyxFQUFFLENBQUMsS0FBSyxDQUFDLE9BQU8sRUFBRSx5QkFBeUIsQ0FBQyxDQUFBO0lBQ2xFLENBQUMsQ0FBQyxDQUFDO0lBQ0gsRUFBRSxDQUFDLElBQUksQ0FBQyxlQUFlLEVBQUUsS0FBSztRQUMxQixNQUFNLE9BQU8sR0FBRyxNQUFNLENBQUM7UUFDdkIsTUFBTSxPQUFPLEdBQUcsTUFBTSxNQUFNLENBQUMsVUFBVSxFQUFFLENBQUM7UUFDMUMsTUFBTSxhQUFhLEdBQUcsTUFBTSxNQUFNLENBQUMsV0FBVyxDQUFDLE9BQU8sQ0FBQyxDQUFDO1FBQ3hELE1BQU0sU0FBUyxHQUFHLGFBQWEsQ0FBQyxPQUFPLEVBQUUsYUFBYSxDQUFDLENBQUM7UUFDeEQsTUFBTSxDQUFDLFNBQVMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxLQUFLLENBQUMsT0FBTyxFQUFFLHlCQUF5QixDQUFDLENBQUE7SUFDbEUsQ0FBQyxDQUFDLENBQUM7QUFDUCxDQUFDLENBQUMsQ0FBQSJ9