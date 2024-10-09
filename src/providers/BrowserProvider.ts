import {assertArgument, Eip1193Provider, JsonRpcApiProviderOptions, JsonRpcError, JsonRpcPayload, JsonRpcResult} from "ethers";
import type {Networkish} from "ethers/lib.commonjs/providers/network";
import {BrowserProviderOptions} from "ethers/lib.commonjs/providers/provider-browser";
import {JsonRpcApiPollingProvider} from "./JsonRpcApiPollingProvider";
import {JsonRpcSigner} from "./JsonRpcSigner"
import {OnboardInfo} from "../types";

export class BrowserProvider extends JsonRpcApiPollingProvider {
    
    #request: (method: string, params: Array<any> | Record<string, any>) => Promise<any>;

    /**
     *  Connnect to the %%ethereum%% provider, optionally forcing the
     *  %%network%%.
     */
    constructor(ethereum: Eip1193Provider, network?: Networkish, _options?: BrowserProviderOptions) {
        // Copy the options
        const options: JsonRpcApiProviderOptions = Object.assign({ },
          ((_options != null) ? _options: { }),
          { batchMaxCount: 1 });

        assertArgument(ethereum && ethereum.request, "invalid EIP-1193 provider", "ethereum", ethereum);

        super(network, options);

        this.#request = async (method: string, params: Array<any> | Record<string, any>) => {
            const payload = { method, params };
            this.emit("debug", { action: "sendEip1193Request", payload });
            try {
                const result = await ethereum.request(payload);
                this.emit("debug", { action: "receiveEip1193Result", result });
                return result;
            } catch (e: any) {
                const error = new Error(e.message);
                (<any>error).code = e.code;
                (<any>error).data = e.data;
                (<any>error).payload = payload;
                this.emit("debug", { action: "receiveEip1193Error", error });
                throw error;
            }
        };
    }

    async send(method: string, params: Array<any> | Record<string, any>): Promise<any> {
        await this._start();

        return await super.send(method, params);
    }

    async _send(payload: JsonRpcPayload | Array<JsonRpcPayload>): Promise<Array<JsonRpcResult | JsonRpcError>> {
        assertArgument(!Array.isArray(payload), "EIP-1193 does not support batch request", "payload", payload);

        try {
            const result = await this.#request(payload.method, payload.params || [ ]);
            return [ { id: payload.id, result } ];
        } catch (e: any) {
            return [ {
                id: payload.id,
                error: { code: e.code, data: e.data, message: e.message }
            } ];
        }
    }

    getRpcError(payload: JsonRpcPayload, error: JsonRpcError): Error {

        error = JSON.parse(JSON.stringify(error));

        // EIP-1193 gives us some machine-readable error codes, so rewrite
        // them into 
        switch (error.error.code || -1) {
            case 4001:
                error.error.message = `ethers-user-denied: ${ error.error.message }`;
                break;
            case 4200:
                error.error.message = `ethers-unsupported: ${ error.error.message }`;
                break;
        }

        return super.getRpcError(payload, error);
    }

    /**
     *  Resolves to ``true`` if the provider manages the %%address%%.
     */
    async hasSigner(address: number | string): Promise<boolean> {
        if (address == null) { address = 0; }

        const accounts = await this.send("eth_accounts", [ ]);
        if (typeof(address) === "number") {
            return (accounts.length > address);
        }

        address = address.toLowerCase();
        return accounts.filter((a: string) => (a.toLowerCase() === address)).length !== 0;
    }

    async getSigner(address?: number | string, userOnboardInfo?: OnboardInfo): Promise<JsonRpcSigner> {
        if (address == null) { address = 0; }

        if (!(await this.hasSigner(address))) {
            try {
                //const resp = 
                await this.#request("eth_requestAccounts", [ ]);
                //console.log("RESP", resp);

            } catch (error: any) {
                const payload = error.payload;
                throw this.getRpcError(payload, { id: payload.id, error });
            }
        }

        return await super.getSigner(address, userOnboardInfo);
    }
}
