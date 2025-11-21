import {Provider, SigningKey, Wallet as BaseWallet} from "ethers";
import {CotiNetwork, OnboardInfo, RsaKeyPair} from "../types";
import {
    buildStringInputText,
    ctString,
    ctUint,
    ctUint256,
    decryptString,
    decryptUint,
    decryptUint256,
    itString,
    itUint,
    itUint256,
    prepareIT,
    prepareIT256
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

    async encryptValue(
        plaintextValue: bigint | number | string, 
        contractAddress: string, 
        functionSelector: string,
        eip191: boolean = false
    ): Promise<itUint | itUint256 | itString> {
        if (this._userOnboardInfo?.aesKey === null || this._userOnboardInfo?.aesKey === undefined) {
            if (this._autoOnboard) {
                console.warn("user AES key is not defined and need to onboard or recovered.")
                await this.generateOrRecoverAes()
                if (!this._userOnboardInfo || this._userOnboardInfo.aesKey === undefined || this._userOnboardInfo.aesKey === null) {
                    throw new Error("user AES key is not defined and cannot be onboarded or recovered.")

                }
            } else {
                throw new Error("user AES key is not defined and auto onboard is off.")
            }
        }
        const value = typeof plaintextValue === 'number' ? BigInt(plaintextValue) : plaintextValue

        let result;

        if (typeof value === 'bigint') {
            // Check the bit size to determine which function to use
            const bitSize = value.toString(2).length
            
            if (bitSize > 128) {
                // Use prepareIT256 for values > 128 bits
                result = prepareIT256(
                    value,
                    {
                        wallet: this as any,
                        userKey: this._userOnboardInfo.aesKey
                    },
                    contractAddress,
                    functionSelector
                )
            } else {
                // Use prepareIT for values <= 128 bits
                result = prepareIT(
                    value,
                    {
                        wallet: this as any,
                        userKey: this._userOnboardInfo.aesKey
                    },
                    contractAddress,
                    functionSelector
                );
            } 
        } else if (typeof value === 'string') {
            result = buildStringInputText(value, {
                wallet: this as any,
                userKey: this._userOnboardInfo.aesKey
            }, contractAddress, functionSelector);
        } else {
            throw new Error("Unknown type");
        }

        return result;
    }

    async decryptValue(ciphertext: ctUint | ctUint256 | ctString): Promise<bigint | string> {
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

        // Handle null or undefined
        if (ciphertext === null || ciphertext === undefined) {
            throw new Error("Ciphertext is null or undefined")
        }

        // Check if it's ctUint256 (object with ciphertextHigh and ciphertextLow)
        if (typeof ciphertext === 'object' && 'ciphertextHigh' in ciphertext && 'ciphertextLow' in ciphertext) {
            return decryptUint256(ciphertext as ctUint256, this._userOnboardInfo.aesKey)
        }

        // Check if it's ctString (object with value array)
        if (typeof ciphertext === 'object' && 'value' in ciphertext && Array.isArray((ciphertext as ctString).value)) {
            return decryptString(ciphertext as ctString, this._userOnboardInfo.aesKey)
        }

        // Otherwise it's ctUint (bigint) - works for all uint sizes (8, 16, 32, 64, 128)
        if (typeof ciphertext === 'bigint') {
            return decryptUint(ciphertext, this._userOnboardInfo.aesKey)
        }

        // If it's an array/tuple, try to extract the first element
        if (Array.isArray(ciphertext) && ciphertext.length > 0) {
            return this.decryptValue(ciphertext[0])
        }

        throw new Error(`Unknown ciphertext type: ${typeof ciphertext}, value: ${JSON.stringify(ciphertext)}`)
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
