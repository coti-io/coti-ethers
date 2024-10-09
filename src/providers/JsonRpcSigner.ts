import {ctString, ctUint, decodeUint, decryptString, decryptUint, encodeKey, encodeUint, encrypt, itString, itUint} from "@coti-io/coti-sdk-typescript";
import {JsonRpcSigner as BaseJsonRpcSigner, JsonRpcApiProvider, solidityPacked} from "ethers"
import {CotiNetwork, OnboardInfo, RsaKeyPair} from "../types";
import {ONBOARD_CONTRACT_ADDRESS} from "../utils/constants";
import {getAccountBalance, getDefaultProvider, onboard, recoverAesFromTx} from "../utils";

const EIGHT_BYTES = 8

export class JsonRpcSigner extends BaseJsonRpcSigner {
    private _autoOnboard: boolean = true;
    private _userOnboardInfo?: OnboardInfo;

    constructor(provider: JsonRpcApiProvider, address: string, userOnboardInfo?: OnboardInfo) {
        super(provider, address)
        this._userOnboardInfo = userOnboardInfo;
    }

    async #buildInputText(
        plaintext: bigint,
        userKey: string,
        contractAddress: string,
        functionSelector: string
    ): Promise<itUint> {
        if (plaintext >= BigInt(2) ** BigInt(64)) {
            throw new RangeError("Plaintext size must be 64 bits or smaller.")
        }
    
        // Convert the plaintext to bytes
        const plaintextBytes = encodeUint(plaintext)
    
        // Convert user key to bytes
        const keyBytes = encodeKey(userKey)
    
        // Encrypt the plaintext using AES key
        const {ciphertext, r} = encrypt(keyBytes, plaintextBytes)
        const ct = new Uint8Array([...ciphertext, ...r])
    
        // Convert the ciphertext to BigInt
        const ctInt = decodeUint(ct)
    
        
        let signature: Uint8Array | string
        
        const message = solidityPacked(
            ["address", "address", "bytes4", "uint256"],
            [this.address, contractAddress, functionSelector, ctInt]
        )

        const messageBytes = new Uint8Array((message.length - 2) / 2)

        for (let i = 0; i < message.length - 2; i += 2) {
            const byte = parseInt(message.substring(i + 2, i + 4), 16)
            messageBytes[i / 2] = byte
        }

        signature = await this.signMessage(messageBytes)
    
        return {
            ciphertext: ctInt,
            signature
        }
    }

    async #buildStringInputText(
        plaintext: string,
        userKey: string,
        contractAddress: string,
        functionSelector: string
    ): Promise<itString> {
        let encoder = new TextEncoder()

        // Encode the plaintext string into bytes (UTF-8 encoded)        
        let encodedStr = encoder.encode(plaintext)

        const inputText = {
            ciphertext: { value: new Array<bigint>() },
            signature: new Array<Uint8Array | string>()
        }

        // Process the encoded string in chunks of 8 bytes
        // We use 8 bytes since we will use ctUint64 to store
        // each chunk of 8 characters
        for (let startIdx = 0; startIdx < encodedStr.length; startIdx += EIGHT_BYTES) {
            const endIdx = Math.min(startIdx + EIGHT_BYTES, encodedStr.length)

            const byteArr = new Uint8Array([...encodedStr.slice(startIdx, endIdx), ...new Uint8Array(EIGHT_BYTES - (endIdx - startIdx))]) // pad the end of the string with zeros if needed

            const it = await this.#buildInputText(
                decodeUint(byteArr), // convert the 8-byte hex string into a number
                userKey,
                contractAddress,
                functionSelector
            )

            inputText.ciphertext.value.push(it.ciphertext)
            inputText.signature.push(it.signature)
        }

        return inputText
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

    enableAutoOnboard() {
        this._autoOnboard = true;
    }

    disableAutoOnboard() {
        this._autoOnboard = false;
    }

    clearUserOnboardInfo() {
        this._userOnboardInfo = undefined
    }

    async encryptValue(plaintextValue: bigint | number | string, contractAddress: string, functionSelector: string): Promise<itUint | itString> {
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
            result = await this.#buildInputText(
                value,
                this._userOnboardInfo.aesKey,
                contractAddress,
                functionSelector
            );
        } else if (typeof value === 'string') {
            result = await this.#buildStringInputText(
                value,
                this._userOnboardInfo.aesKey,
                contractAddress,
                functionSelector
            );
        } else {
            throw new Error("Unknown type");
        }

        return result;
    }

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