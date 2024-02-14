import { RevoProvider } from "./RevoProvider";
export declare class RevoFunctionProvider extends RevoProvider {
    readonly fn: Function;
    constructor(fn: Function);
    send(method: string, params: Array<any>): Promise<any>;
}
