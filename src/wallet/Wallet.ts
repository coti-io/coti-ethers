import {Provider, SigningKey, Wallet as BaseWallet} from "ethers";
import {CotiNetwork, OnboardInfo, RsaKeyPair} from "../types";
import {
    buildStringInputText,
    buildUint8InputText,
    buildUint16InputText,
    buildUint32InputText,
    buildUint64InputText,
    buildUint128InputText,
    buildUint256InputText,
    ctString,
    ctUint8,
    ctUint16,
    ctUint32,
    ctUint64,
    ctUint128,
    ctUint256,
    decryptString,
    decryptUint8,
    decryptUint16,
    decryptUint32,
    decryptUint64,
    decryptUint128,
    decryptUint256,
    itString,
    itUint8,
    itUint16,
    itUint32,
    itUint64,
    itUint128,
    itUint256
} from "@coti-io/coti-sdk-typescript";
import {getAccountBalance, getDefaultProvider, onboard, recoverAesFromTx} from "../utils";
import {ONBOARD_CONTRACT_ADDRESS} from "../utils/constants";


export class Wallet extends BaseWallet {
    private _autoOnboard: boolean = true;
    private _userOnboardInfo?: OnboardInfo;

    constructor(
        privateKey: string | SigningKey,
        provider?: Provider | null,
        userOnboardInfo?: OnboardInfo
    ) {
        super(privateKey, provider);
        this._userOnboardInfo = userOnboardInfo;
    }

    getAutoOnboard(): boolean {
        return this._autoOnboard;
    }

    getUserOnboardInfo(): OnboardInfo | undefined {
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

    async #checkAesKey() {
        if (this._userOnboardInfo?.aesKey !== null && this._userOnboardInfo?.aesKey !== undefined) return

        if (!this._autoOnboard) {
            throw new Error("user AES key is not defined and auto onboard is off.")
        }

        console.warn("user AES key is not defined and need to onboard or recovered.")
        await this.generateOrRecoverAes()
        if (!this._userOnboardInfo || this._userOnboardInfo.aesKey === undefined || this._userOnboardInfo.aesKey === null) {
            throw new Error("user AES key is not defined and cannot be onboarded or recovered.")

        }
    }

    async encryptUint8(plaintextValue: bigint | number, contractAddress: string, functionSelector: string): Promise<itUint8> {
        await this.#checkAesKey()

        const value = typeof plaintextValue === 'number' ? BigInt(plaintextValue) : plaintextValue

        return buildUint8InputText(
            value,
            { wallet: this, userKey: this._userOnboardInfo!.aesKey! },
            contractAddress,
            functionSelector
        )
    }

    async encryptUint16(plaintextValue: bigint | number, contractAddress: string, functionSelector: string): Promise<itUint16> {
        await this.#checkAesKey()

        const value = typeof plaintextValue === 'number' ? BigInt(plaintextValue) : plaintextValue

        return buildUint16InputText(
            value,
            { wallet: this, userKey: this._userOnboardInfo!.aesKey! },
            contractAddress,
            functionSelector
        )
    }

    async encryptUint32(plaintextValue: bigint | number, contractAddress: string, functionSelector: string): Promise<itUint32> {
        await this.#checkAesKey()

        const value = typeof plaintextValue === 'number' ? BigInt(plaintextValue) : plaintextValue

        return buildUint32InputText(
            value,
            { wallet: this, userKey: this._userOnboardInfo!.aesKey! },
            contractAddress,
            functionSelector
        )
    }

    async encryptUint64(plaintextValue: bigint | number, contractAddress: string, functionSelector: string): Promise<itUint64> {
        await this.#checkAesKey()

        const value = typeof plaintextValue === 'number' ? BigInt(plaintextValue) : plaintextValue

        return buildUint64InputText(
            value,
            { wallet: this, userKey: this._userOnboardInfo!.aesKey! },
            contractAddress,
            functionSelector
        )
    }

    async encryptUint128(plaintextValue: bigint | number, contractAddress: string, functionSelector: string): Promise<itUint128> {
        await this.#checkAesKey()

        const value = typeof plaintextValue === 'number' ? BigInt(plaintextValue) : plaintextValue

        return buildUint128InputText(
            value,
            { wallet: this, userKey: this._userOnboardInfo!.aesKey! },
            contractAddress,
            functionSelector
        )
    }

    async encryptUint256(plaintextValue: bigint | number, contractAddress: string, functionSelector: string): Promise<itUint256> {
        await this.#checkAesKey()

        const value = typeof plaintextValue === 'number' ? BigInt(plaintextValue) : plaintextValue

        return buildUint256InputText(
            value,
            { wallet: this, userKey: this._userOnboardInfo!.aesKey! },
            contractAddress,
            functionSelector
        )
    }

    async encryptString(plaintextValue: string, contractAddress: string, functionSelector: string): Promise<itString> {
        await this.#checkAesKey()

        return buildStringInputText(
            plaintextValue,
            { wallet: this, userKey: this._userOnboardInfo!.aesKey! },
            contractAddress,
            functionSelector
        )
    }

    async decryptUint8(ciphertext: ctUint8): Promise<bigint> {
        await this.#checkAesKey()

        return decryptUint8(ciphertext, this._userOnboardInfo!.aesKey!)
    }

    async decryptUint16(ciphertext: ctUint16): Promise<bigint> {
        await this.#checkAesKey()

        return decryptUint16(ciphertext, this._userOnboardInfo!.aesKey!)
    }

    async decryptUint32(ciphertext: ctUint32): Promise<bigint> {
        await this.#checkAesKey()

        return decryptUint32(ciphertext, this._userOnboardInfo!.aesKey!)
    }

    async decryptUint64(ciphertext: ctUint64): Promise<bigint> {
        await this.#checkAesKey()

        return decryptUint64(ciphertext, this._userOnboardInfo!.aesKey!)
    }

    async decryptUint128(ciphertext: ctUint128): Promise<bigint> {
        await this.#checkAesKey()

        return decryptUint128(ciphertext, this._userOnboardInfo!.aesKey!)
    }

    async decryptUint256(ciphertext: ctUint256): Promise<bigint> {
        await this.#checkAesKey()

        return decryptUint256(ciphertext, this._userOnboardInfo!.aesKey!)
    }

    async decryptString(ciphertext: ctString): Promise<string> {
        await this.#checkAesKey()

        return decryptString(ciphertext, this._userOnboardInfo!.aesKey!)
    }

    enableAutoOnboard() {
        this._autoOnboard = true;
    }

    disableAutoOnboard() {
        this._autoOnboard = false;
    }

    clearUserOnboardInfo() {
        this._userOnboardInfo = undefined
    }

    async generateOrRecoverAes(onboardContractAddress: string = ONBOARD_CONTRACT_ADDRESS) {
        if (this._userOnboardInfo?.aesKey)
            return
        else if (this._userOnboardInfo && this._userOnboardInfo.rsaKey && this._userOnboardInfo.txHash)
            this.setAesKey(await recoverAesFromTx(this._userOnboardInfo.txHash, this._userOnboardInfo.rsaKey,
                onboardContractAddress, this.provider))
        else {
            const accountBalance = await getAccountBalance(this.address, this.provider || getDefaultProvider(CotiNetwork.Testnet))
            if (accountBalance > BigInt(0))
                this.setUserOnboardInfo(await onboard(onboardContractAddress, this))
            else
                throw new Error("Account balance is 0 so user cannot be onboarded.")
        }

    }

}
