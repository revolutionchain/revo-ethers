import { RevoContractFactory as ContractFactory } from './RevoContractFactory';
import { isStandard, hasByteCode } from './ContractJSON';
// @ts-ignore
export async function deployContract(wallet, factoryOrContractJson, args = [], overrideOptions = {}) {
    if ('abi' in factoryOrContractJson) {
        return deployFromJson(wallet, factoryOrContractJson, args, overrideOptions);
    }
    else {
        const Factory = factoryOrContractJson;
        const contractFactory = new Factory(wallet);
        const contract = await contractFactory.deploy(...args, overrideOptions);
        await contract.deployed();
        return contract;
    }
}
// @ts-ignore
async function deployFromJson(wallet, contractJson, args, overrideOptions) {
    const bytecode = isStandard(contractJson) ? contractJson.evm.bytecode : contractJson.bytecode;
    if (!hasByteCode(bytecode)) {
        throw new Error('Cannot deploy contract with empty bytecode');
    }
    const factory = new ContractFactory(contractJson.abi, bytecode, wallet);
    const contract = await factory.deploy(...args, {
        ...overrideOptions
    });
    await contract.deployed();
    return contract;
}
