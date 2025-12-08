import {Provider, SigningKey, Wallet as BaseWallet} from "ethers";
import {CotiNetwork, OnboardInfo, RsaKeyPair, ctUint256, itUint256} from "../types";
import {
    buildStringInputText,
    ctString,
    ctUint,
    decryptString,
    decryptUint,
    decryptUint256,
    itString,
    itUint,
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


    /**
     * Ensures AES key is available, handles onboarding if needed
     */
    private async _ensureAesKey(): Promise<void> {
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
    }

    /**
     * Encrypts values up to 128 bits (uses prepareIT)
     */
    async encryptValue(
        plaintextValue: bigint | number | string, 
        contractAddress: string, 
        functionSelector: string,
    ): Promise<itUint | itString> {
        await this._ensureAesKey();
        
        const value = typeof plaintextValue === 'number' ? BigInt(plaintextValue) : plaintextValue

        if (typeof value === 'bigint') {
            const bitSize = value.toString(2).length
            
            if (bitSize > 128) {
                throw new Error("encryptValue: values larger than 128 bits are not supported");
            }
            
            return prepareIT(
                value,
                {
                    wallet: this as any,
                    userKey: this._userOnboardInfo!.aesKey!
                },
                contractAddress,
                functionSelector
            );
        } else if (typeof value === 'string') {
            return buildStringInputText(
                value,
                {
                    wallet: this as any,
                    userKey: this._userOnboardInfo!.aesKey!
                },
                contractAddress,
                functionSelector
            );
        } else {
            throw new Error("Unknown type");
        }
    }

    // Encrypts values up to 256 bits (uses prepareIT256)
    async encryptValue256(
        plaintextValue: bigint | number,
        contractAddress: string,
        functionSelector: string
    ): Promise<itUint256> {
        await this._ensureAesKey();
        
        const value = typeof plaintextValue === 'number' ? BigInt(plaintextValue) : plaintextValue;
        const bitSize = value.toString(2).length;
        
        if (bitSize > 256) {
            throw new Error("encryptValue256: values larger than 256 bits are not supported");
        }
        
        return prepareIT256(
            value,
            {
                wallet: this as any,
                userKey: this._userOnboardInfo!.aesKey!
            },
            contractAddress,
            functionSelector
        );
    }

    /**
     * Decrypts ctUint256 ciphertexts (uses decryptUint256)
     * Only accepts ciphertexts matching ctUint256 type
     */
    async decryptValue256(ciphertext: ctUint256): Promise<bigint> {
        await this._ensureAesKey();
        return decryptUint256(ciphertext, this._userOnboardInfo!.aesKey!);
    }

    /**
     * Decrypts ctUint and ctString ciphertexts
     */
    async decryptValue(ciphertext: ctUint | ctString): Promise<bigint | string> {
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
