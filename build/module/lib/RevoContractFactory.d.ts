import { ContractFactory, ContractInterface, BytesLike, Signer, Contract } from "ethers";
export declare class RevoContractFactory extends ContractFactory {
    constructor(contractInterface: ContractInterface, bytecode: BytesLike | {
        object: string;
    }, signer?: Signer);
    deploy(...args: Array<any>): Promise<Contract>;
}
