import {JsonRpcApiProvider as BaseJsonRpcApiProvider, getAddress, JsonRpcApiProviderOptions, Networkish, resolveProperties} from "ethers"
import {JsonRpcSigner} from "./JsonRpcSigner"
import {OnboardInfo} from "../types";

export abstract class JsonRpcApiProvider extends BaseJsonRpcApiProvider {

    constructor(network?: Networkish, options?: JsonRpcApiProviderOptions) {
        super(network, options)
    }

    async getSigner(address?: number | string, userOnboardInfo?: OnboardInfo): Promise<JsonRpcSigner> {
        if (address == null) { address = 0; }

        const accountsPromise = this.send("eth_accounts", [ ]);

        // Account index
        if (typeof(address) === "number") {
            const accounts = <Array<string>>(await accountsPromise);
            if (address >= accounts.length) { throw new Error("no such account"); }
            return new JsonRpcSigner(this, accounts[address], userOnboardInfo);
        }

        const { accounts } = await resolveProperties({
            network: this.getNetwork(),
            accounts: accountsPromise
        });

        // Account address
        address = getAddress(address);
        for (const account of accounts) {
            if (getAddress(account) === address) {
                return new JsonRpcSigner(this, address, userOnboardInfo);
            }
        }

        throw new Error("invalid account");
    }
}