import {BrowserProvider as BaseBrowserProvider, Eip1193Provider, Provider} from "ethers";
import {Wallet} from "./Wallet";
import type {Networkish} from "ethers/lib.commonjs/providers/network";
import {BrowserProviderOptions} from "ethers/lib.commonjs/providers/provider-browser";
import {OnboardInfo} from "./types";


export class BrowserProvider extends BaseBrowserProvider {

    private wallet: Wallet | null = null;

    constructor(ethereum: Eip1193Provider, network?: Networkish, _options?: BrowserProviderOptions, wallet: Wallet | null = null) {
        super(ethereum);
        this.wallet = wallet;
    }

    async encryptValue(plaintextValue: bigint | number | string, contractAddress: string, functionSelector: string) {
        if (!this.wallet) {
            throw new Error("wallet is undefined")
        }
        return this.wallet.encryptValue(plaintextValue, contractAddress, functionSelector)
    }

    async decryptValue(ciphertext: bigint | Array<bigint>) {
        if (!this.wallet) {
            throw new Error("wallet is not defined. please create one.")
        }
        return this.wallet.decryptValue(ciphertext)
    }

    createWallet(privateKey: string, provider: Provider | null | undefined, onboardInfo: OnboardInfo | null = null) {
        this.wallet = new Wallet(privateKey, provider, onboardInfo)
    }

    clearWallet() {
        this.wallet = null
    }

}
