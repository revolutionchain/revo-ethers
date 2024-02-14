// @ts-nocheck
const { BigNumber } = require("@ethersproject/bignumber");
const { expect } = require("chai");
const { ethers } = require("ethers")
const { RevoWallet } = require("../../build/main/lib/RevoWallet");
const { RevoProvider } = require("../../build/main/lib/RevoProvider");
const {
    RevoContractFactory,
} = require("../../build/main/lib/RevoContractFactory");
const { generateContractAddress } = require('../../build/main/lib/helpers/utils')
const provider = new RevoProvider("http://localhost:23890");

// hash160PubKey/address -> 0xcdf409a70058bfc54ada1ee3422f1ef28d0d267d
const signer = new RevoWallet(
    "99dda7e1a59655c9e02de8592be3b914df7df320e72ce04ccf0427f9a366ec6e",
    provider
);
// hash160PubKey/address -> 0x30a41759e2fec594fbb90ea2b212c9ef8074e227
const signerNoRevo = new RevoWallet(
    "61fd08e21110d908cf8dc20bb243a96e2dc0d29169b4fec09594c39e4384125a",
    provider
);

const ADOPTION_ABI = [
    {
        "inputs": [
            {
                "internalType": "uint256",
                "name": "",
                "type": "uint256"
            }
        ],
        "name": "adopters",
        "outputs": [
            {
                "internalType": "address",
                "name": "",
                "type": "address"
            }
        ],
        "stateMutability": "view",
        "type": "function",
        "constant": true
    },
    {
        "inputs": [
            {
                "internalType": "uint256",
                "name": "petId",
                "type": "uint256"
            }
        ],
        "name": "adopt",
        "outputs": [
            {
                "internalType": "uint256",
                "name": "",
                "type": "uint256"
            }
        ],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "getAdopters",
        "outputs": [
            {
                "internalType": "address[16]",
                "name": "",
                "type": "address[16]"
            }
        ],
        "stateMutability": "view",
        "type": "function",
        "constant": true
    }
];

const ADOPTION_BYTECODE = "0x608060405234801561001057600080fd5b5061021c806100206000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c80633de4eb171461004657806343ae80d3146100645780638588b2c51461008f575b600080fd5b61004e6100b0565b60405161005b919061017c565b60405180910390f35b6100776100723660046101b7565b6100f6565b6040516001600160a01b03909116815260200161005b565b6100a261009d3660046101b7565b610116565b60405190815260200161005b565b6100b861015d565b604080516102008101918290529060009060109082845b81546001600160a01b031681526001909101906020018083116100cf575050505050905090565b6000816010811061010657600080fd5b01546001600160a01b0316905081565b6000600f82111561012657600080fd5b336000836010811061013a5761013a6101d0565b0180546001600160a01b0319166001600160a01b03929092169190911790555090565b6040518061020001604052806010906020820280368337509192915050565b6102008101818360005b60108110156101ae5781516001600160a01b0316835260209283019290910190600101610186565b50505092915050565b6000602082840312156101c957600080fd5b5035919050565b634e487b7160e01b600052603260045260246000fdfea264697066735822122030627c28006c8c423df956d43c0dfe9d3942dc066cfba338ceedb7aea227c2d264736f6c63430008090033"

describe("Adoption", function () {
    context("ethers.Contract", function () {
        it("can deploy and adopt", async function () {
            const adoption = new RevoContractFactory(ADOPTION_ABI, ADOPTION_BYTECODE, signer);
            const deployment = await adoption.deploy({
                gasPrice: "0x190"
            });
            expect(deployment.address).to.equal(`0x${generateContractAddress(deployment.deployTransaction.hash.split("0x")[1])}`)
            await deployment.deployed();
            const contract = new ethers.Contract(deployment.address, ADOPTION_ABI, signer);
            for (let i = 0; i <= 1; i++) {
                const adopt = await contract.adopt(0, {
                    gasPrice: "0x190"
                });
                await adopt.wait()
            }

            const adopters = await contract.getAdopters();
            expect(adopters[0]).to.equal("0xCDF409A70058BFC54AdA1eE3422f1EF28d0d267D");
        });
    });

    context("RevoContractFactory", function () {
        it("can deploy and adopt", async function () {
            const adoption = new RevoContractFactory(ADOPTION_ABI, ADOPTION_BYTECODE, signer);
            const deployment = await adoption.deploy({
                gasPrice: "0x190"
            });
            expect(deployment.address).to.equal(`0x${generateContractAddress(deployment.deployTransaction.hash.split("0x")[1])}`)
            await deployment.deployed();
            for (let i = 0; i <= 1; i++) {
                const adopt = await deployment.adopt(0, {
                    gasPrice: "0x190"
                });
                await adopt.wait()
            }

            const adopters = await deployment.getAdopters();
            expect(adopters[0]).to.equal("0xCDF409A70058BFC54AdA1eE3422f1EF28d0d267D");
        });
    });
})