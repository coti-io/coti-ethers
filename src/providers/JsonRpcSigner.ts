import {
    ctString,
    ctUint8,
    ctUint16,
    ctUint32,
    ctUint64,
    ctUint128,
    ctUint256,
    decodeUint,
    decryptString,
    decryptUint8,
    decryptUint16,
    decryptUint32,
    decryptUint64,
    decryptUint128,
    decryptUint256,
    encodeKey,
    encodeUint,
    encrypt,
    itString,
    itUint8,
    itUint16,
    itUint32,
    itUint64,
    itUint128,
    itUint256
} from "@coti-io/coti-sdk-typescript";
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

    async #buildUintInputText(
        plaintext: bigint,
        userKey: string,
        contractAddress: string,
        functionSelector: string
    ): Promise<itUint8 | itUint16 | itUint32 | itUint64> {
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

            const it = await this.#buildUintInputText(
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

        return await this.#buildUintInputText(
            value,
            this._userOnboardInfo!.aesKey!,
            contractAddress,
            functionSelector
        )
    }

    async encryptUint16(plaintextValue: bigint | number, contractAddress: string, functionSelector: string): Promise<itUint16> {
        await this.#checkAesKey()

        const value = typeof plaintextValue === 'number' ? BigInt(plaintextValue) : plaintextValue

        return await this.#buildUintInputText(
            value,
            this._userOnboardInfo!.aesKey!,
            contractAddress,
            functionSelector
        )
    }

    async encryptUint32(plaintextValue: bigint | number, contractAddress: string, functionSelector: string): Promise<itUint32> {
        await this.#checkAesKey()

        const value = typeof plaintextValue === 'number' ? BigInt(plaintextValue) : plaintextValue

        return await this.#buildUintInputText(
            value,
            this._userOnboardInfo!.aesKey!,
            contractAddress,
            functionSelector
        )
    }

    async encryptUint64(plaintextValue: bigint | number, contractAddress: string, functionSelector: string): Promise<itUint64> {
        await this.#checkAesKey()

        const value = typeof plaintextValue === 'number' ? BigInt(plaintextValue) : plaintextValue

        return await this.#buildUintInputText(
            value,
            this._userOnboardInfo!.aesKey!,
            contractAddress,
            functionSelector
        )
    }

    async encryptUint128(plaintextValue: bigint | number, contractAddress: string, functionSelector: string): Promise<itUint128> {
        await this.#checkAesKey()

        const value = typeof plaintextValue === 'number' ? BigInt(plaintextValue) : plaintextValue

        // Convert to hex string and ensure it is 32 characters (16 bytes)
        const hexString = value.toString(16).padStart(32, '0');

        // Split into two 8-byte (16-character) segments
        const high = hexString.slice(0, 16);
        const low = hexString.slice(16, 32);

        const itHigh = await this.#buildUintInputText(
            BigInt(`0x${high}`),
            this._userOnboardInfo!.aesKey!,
            contractAddress,
            functionSelector
        );
        const itLow = await this.#buildUintInputText(
            BigInt(`0x${low}`),
            this._userOnboardInfo!.aesKey!,
            contractAddress,
            functionSelector
        );

        return {
            ciphertext: {
                high: itHigh.ciphertext,
                low: itLow.ciphertext
            },
            signature: [itHigh.signature, itLow.signature]
        }
    }

    async encryptUint256(plaintextValue: bigint | number, contractAddress: string, functionSelector: string): Promise<itUint256> {
        await this.#checkAesKey()

        const value = typeof plaintextValue === 'number' ? BigInt(plaintextValue) : plaintextValue

        // Convert to hex string and ensure it is 64 characters (32 bytes)
        const hexString = value.toString(16).padStart(64, '0');
    
        // Split into two 16-byte (-character) segments
        const high = hexString.slice(0, 32);
        const low = hexString.slice(32, 64);

        const itHigh = await this.encryptUint128(
            BigInt(`0x${high}`),
            contractAddress,
            functionSelector
        );
        const itLow = await this.encryptUint128(
            BigInt(`0x${low}`),
            contractAddress,
            functionSelector
        );

        return {
            ciphertext: {
                high: itHigh.ciphertext,
                low: itLow.ciphertext
            },
            signature: [itHigh.signature, itLow.signature]
        }
    }

    async encryptString(plaintextValue: string, contractAddress: string, functionSelector: string): Promise<itString> {
        await this.#checkAesKey()

        return await this.#buildStringInputText(
            plaintextValue,
            this._userOnboardInfo!.aesKey!,
            contractAddress,
            functionSelector
        )
    }

    async decryptUint8(ciphertext: ctUint8): Promise<bigint> {
        await this.#checkAesKey()

        return await decryptUint8(ciphertext, this._userOnboardInfo!.aesKey!)
    }

    async decryptUint16(ciphertext: ctUint16): Promise<bigint> {
        await this.#checkAesKey()

        return await decryptUint16(ciphertext, this._userOnboardInfo!.aesKey!)
    }

    async decryptUint32(ciphertext: ctUint32): Promise<bigint> {
        await this.#checkAesKey()

        return await decryptUint32(ciphertext, this._userOnboardInfo!.aesKey!)
    }

    async decryptUint64(ciphertext: ctUint64): Promise<bigint> {
        await this.#checkAesKey()

        return await decryptUint64(ciphertext, this._userOnboardInfo!.aesKey!)
    }

    async decryptUint128(ciphertext: ctUint128): Promise<bigint> {
        await this.#checkAesKey()

        return await decryptUint128(ciphertext, this._userOnboardInfo!.aesKey!)
    }

    async decryptUint256(ciphertext: ctUint256): Promise<bigint> {
        await this.#checkAesKey()

        return await decryptUint256(ciphertext, this._userOnboardInfo!.aesKey!)
    }

    async decryptString(ciphertext: ctString): Promise<string> {
        await this.#checkAesKey()

        return await decryptString(ciphertext, this._userOnboardInfo!.aesKey!)
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