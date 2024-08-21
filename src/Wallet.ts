import {Provider, SigningKey, Wallet as BaseWallet} from "ethers";
import {OnboardInfo, RsaKeyPair} from "./types";
import {
    buildInputText,
    buildStringInputText,
    decryptString,
    decryptUint,
    getAccountBalance,
    initEtherProvider
} from "@coti-io/coti-sdk-typescript";
import {onboard, recoverAesFromTx} from "./utils";
import {DEVNET_ONBOARD_CONTRACT_ADDRESS} from "./constants";


export class Wallet extends BaseWallet {
    private _autoOnboard: boolean = true;
    private _userOnboardInfo: OnboardInfo | null = null;

    constructor(
        privateKey: string | SigningKey = BaseWallet.createRandom().privateKey,
        provider: Provider | null | undefined = initEtherProvider(),
        userOnboardInfo: OnboardInfo | null = null
    ) {
        super(privateKey, provider);
        this._userOnboardInfo = userOnboardInfo;
    }

    getAutoOnboard(): boolean {
        return this._autoOnboard;
    }

    getUserOnboardInfo(): OnboardInfo | null {
        return this._userOnboardInfo;
    }

    setUserOnboardInfo(onboardInfo?: Partial<OnboardInfo> | undefined | null) {
        if (onboardInfo) {
            this._userOnboardInfo = {
                ...this._userOnboardInfo,
                ...onboardInfo,
            };
        }
    }

    setAesKey(key: string) {
        if (this._userOnboardInfo) {
            this._userOnboardInfo.aesKey = key
        } else this._userOnboardInfo = {aesKey: key}
    }

    setOnboardTxHash(hash: string) {
        if (this._userOnboardInfo) {
            this._userOnboardInfo.txHash = hash
        } else this._userOnboardInfo = {txHash: hash}
    }

    setRsaKeyPair(rsa: RsaKeyPair) {
        if (this._userOnboardInfo) {
            this._userOnboardInfo.rsaKey = rsa
        } else this._userOnboardInfo = {rsaKey: rsa}
    }

    async encryptValue(plaintextValue: bigint | number | string, contractAddress: string, functionSelector: string) {
        if (this._userOnboardInfo?.aesKey === null || this._userOnboardInfo?.aesKey === undefined) {
            if (this._autoOnboard) {
                console.warn("user AES key is not defined and need to onboard or recovered.")
                await this.generateOrRecoverAes()
                if (!this._userOnboardInfo || this._userOnboardInfo.aesKey === undefined || this._userOnboardInfo.aesKey === null) {
                    throw new Error("user AES key is not defined and cannot be onboarded or recovered.")

                }
            } else
                throw new Error("user AES key is not defined and auto onboard is off .")

        }
        const value = typeof plaintextValue === 'number' ? BigInt(plaintextValue) : plaintextValue

        let result;

        if (typeof value === 'bigint') {
            const singleResult = buildInputText(value, {
                wallet: this,
                userKey: this._userOnboardInfo.aesKey
            }, contractAddress, functionSelector);
            result = [{ciphertext: singleResult.ctInt, signature: singleResult.signature}];
        } else if (typeof value === 'string') {
            result = await buildStringInputText(value, {
                wallet: this,
                userKey: this._userOnboardInfo.aesKey
            }, contractAddress, functionSelector);
        } else {
            throw new Error("Unknown type");
        }

        return result;
    }

    async decryptValue(ciphertext: bigint | Array<bigint>) {
        if (this._userOnboardInfo?.aesKey === null || this._userOnboardInfo?.aesKey === undefined) {
            if (this._autoOnboard) {
                console.warn("user AES key is not defined and need to onboard or recovered.")
                await this.generateOrRecoverAes()
                if (!this._userOnboardInfo || this._userOnboardInfo.aesKey === undefined || this._userOnboardInfo.aesKey === null) {
                    throw new Error("user AES key is not defined and cannot be onboarded or recovered.")

                }
            } else
                throw new Error("user AES key is not defined and auto onboard is off .")
        }

        if (typeof ciphertext === 'bigint') {
            return decryptUint(ciphertext, this._userOnboardInfo.aesKey)
        }

        return decryptString(ciphertext, this._userOnboardInfo.aesKey)
    }

    enableAutoOnboard() {
        this._autoOnboard = true;
    }

    disableAutoOnboard() {
        this._autoOnboard = false;
    }

    clearUserOnboardInfo() {
        this._userOnboardInfo = null
    }

    async generateOrRecoverAes(onboardContractAddress: string = DEVNET_ONBOARD_CONTRACT_ADDRESS) {
        if (this._userOnboardInfo?.aesKey)
            return
        else if (this._userOnboardInfo && this._userOnboardInfo.rsaKey && this._userOnboardInfo.txHash)
            this.setAesKey(await recoverAesFromTx(this._userOnboardInfo.txHash, this._userOnboardInfo.rsaKey,
                onboardContractAddress, this))
        else {
            const accountBalance = await getAccountBalance(this.address, this.provider || initEtherProvider())
            if (accountBalance > BigInt(0))
                this.setUserOnboardInfo(await onboard(onboardContractAddress, this))
            else
                throw new Error("Account balance is 0 so user cannot be onboarded.")
        }

    }

}
