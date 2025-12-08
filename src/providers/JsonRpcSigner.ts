import {
    ctString,
    ctUint,
    ctUint256,
    decodeUint,
    decryptString,
    decryptUint,
    decryptUint256,
    encodeKey,
    encodeUint,
    encrypt,
    itString,
    itUint,
    itUint256
} from "@coti-io/coti-sdk-typescript";
import {JsonRpcSigner as BaseJsonRpcSigner, JsonRpcApiProvider, solidityPacked, solidityPackedKeccak256, getBytes} from "ethers"
import {CotiNetwork, OnboardInfo, RsaKeyPair} from "../types";
import {ONBOARD_CONTRACT_ADDRESS} from "../utils/constants";
import {getAccountBalance, getDefaultProvider, onboard, recoverAesFromTx} from "../utils";

const EIGHT_BYTES = 8
const BLOCK_SIZE = 16 // AES block size in bytes
const CT_SIZE = 32 // 256 bits = 32 bytes
const MAX_PLAINTEXT_BIT_SIZE = 256

// Helper function to write 128-bit bigint to buffer (big-endian)
function writeBigUInt128BE(buf: Uint8Array, value: bigint) {
    for (let i = 15; i >= 0; i--) {
        buf[i] = Number(value & BigInt(0xff))
        value >>= BigInt(8)
    }
}

// Helper function to write 256-bit bigint to buffer (big-endian)
function writeBigUInt256BE(buf: Uint8Array, value: bigint) {
    for (let i = 31; i >= 0; i--) {
        buf[i] = Number(value & BigInt(0xff))
        value >>= BigInt(8)
    }
}

export class JsonRpcSigner extends BaseJsonRpcSigner {
    private _autoOnboard: boolean = true;
    private _userOnboardInfo?: OnboardInfo;

    constructor(provider: JsonRpcApiProvider, address: string, userOnboardInfo?: OnboardInfo) {
        super(provider, address)
        this._userOnboardInfo = userOnboardInfo;
    }

    /**
     * Builds input text (itUint) for values up to 128 bits
     * Equivalent to prepareIT from SDK, but uses signMessage() for MetaMask compatibility
     */
    async #prepareIT(
        plaintext: bigint,
        userKey: string,
        contractAddress: string,
        functionSelector: string
    ): Promise<itUint> {
        const plaintextBigInt = BigInt(plaintext)
        const bitSize = plaintextBigInt.toString(2).length
        
        if (bitSize > MAX_PLAINTEXT_BIT_SIZE / 2) { 
            throw new RangeError("Plaintext size must be 128 bits or smaller. Use prepareIT256 for larger values.")
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
    
        // Build the message to sign (same format as SDK's signInputText)
        const message = solidityPacked(
            ["address", "address", "bytes4", "uint256"],
            [this.address, contractAddress, functionSelector, ctInt]
        )

        const messageBytes = new Uint8Array((message.length - 2) / 2)

        for (let i = 0; i < message.length - 2; i += 2) {
            const byte = parseInt(message.substring(i + 2, i + 4), 16)
            messageBytes[i / 2] = byte
        }

        // Sign using signMessage() (MetaMask compatible)
        const signature = await this.signMessage(messageBytes)
    
        return {
            ciphertext: ctInt,
            signature
        }
    }

    /**
     * Builds input text (itUint256) for values up to 256 bits
     * Equivalent to prepareIT256 from SDK, but uses signMessage() for MetaMask compatibility
     */
    async #prepareIT256(
        plaintext: bigint,
        userKey: string,
        contractAddress: string,
        functionSelector: string
    ): Promise<itUint256> {
        const plaintextBigInt = BigInt(plaintext)
        const bitSize = plaintextBigInt.toString(2).length
        
        if (bitSize > MAX_PLAINTEXT_BIT_SIZE) {
            throw new RangeError("Plaintext size must be 256 bits or smaller.")
        }

        const userAesKey = encodeKey(userKey)
        const senderBytes = getBytes(this.address)
        const contractBytes = getBytes(contractAddress)
        const hashFuncBytes = getBytes(functionSelector)

        let ct = new Uint8Array(0)

        if (bitSize <= MAX_PLAINTEXT_BIT_SIZE / 2) {
            // Value fits in 128 bits - encrypt low part, zero high part
            const plaintextBytes = new Uint8Array(BLOCK_SIZE)
            writeBigUInt128BE(plaintextBytes, plaintextBigInt)
            const { ciphertext, r } = encrypt(userAesKey, plaintextBytes)

            const zero = BigInt(0)
            const zeroBytes = new Uint8Array(BLOCK_SIZE)
            writeBigUInt128BE(zeroBytes, zero)
            const { ciphertext: ciphertextHigh, r: rHigh } = encrypt(userAesKey, zeroBytes)

            ct = new Uint8Array([...ciphertextHigh, ...rHigh, ...ciphertext, ...r])
        } else {
            // Value > 128 bits - encrypt both high and low parts
            const plaintextBytes = new Uint8Array(CT_SIZE)
            writeBigUInt256BE(plaintextBytes, plaintextBigInt)
            const high = encrypt(userAesKey, plaintextBytes.slice(0, BLOCK_SIZE))
            const low = encrypt(userAesKey, plaintextBytes.slice(BLOCK_SIZE))
            ct = new Uint8Array([...high.ciphertext, ...high.r, ...low.ciphertext, ...low.r])
        }

        // Build the message to sign (same format as SDK's signIT)
        const message = solidityPackedKeccak256(
            ["bytes", "bytes", "bytes4", "bytes"],
            [senderBytes, contractBytes, hashFuncBytes, ct]
        )

        const messageBytes = getBytes(message)

        // Sign using signMessage() (MetaMask compatible)
        const signature = await this.signMessage(messageBytes)

        // Convert signature from string to Uint8Array if needed
        let signatureBytes: Uint8Array
        if (typeof signature === 'string') {
            signatureBytes = getBytes(signature)
        } else {
            signatureBytes = signature
        }

        // Split ciphertext into high and low parts
        const ciphertextHigh = ct.slice(0, CT_SIZE)
        const ciphertextLow = ct.slice(CT_SIZE)

        // Convert Uint8Array to hex string then to BigInt
        const ciphertextHighHex = Array.from(ciphertextHigh)
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join('')
        const ciphertextLowHex = Array.from(ciphertextLow)
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join('')

        const ciphertextHighUint = BigInt('0x' + ciphertextHighHex)
        const ciphertextLowUint = BigInt('0x' + ciphertextLowHex)

        return { 
            ciphertext: { 
                ciphertextHigh: ciphertextHighUint, 
                ciphertextLow: ciphertextLowUint 
            }, 
            signature: signatureBytes
        }
    }

    /**
     * Builds input text (itString) for string values
     * IMPORTANT: Strings are chunked in 8-byte (64-bit) increments to ensure compatibility
     * with contracts that expect ctUint64. Each chunk is guaranteed to be ≤ 64 bits.
     */
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

        // Process the encoded string in chunks of 8 bytes (64 bits)
        // CRITICAL: We use exactly 8 bytes to ensure each chunk is ≤ 64 bits
        // This is required for contract compatibility (ctUint64)
        // Even though #prepareIT supports up to 128 bits, we limit strings to 64 bits
        for (let startIdx = 0; startIdx < encodedStr.length; startIdx += EIGHT_BYTES) {
            const endIdx = Math.min(startIdx + EIGHT_BYTES, encodedStr.length)

            // Create 8-byte chunk (padded with zeros if needed)
            const byteArr = new Uint8Array([...encodedStr.slice(startIdx, endIdx), ...new Uint8Array(EIGHT_BYTES - (endIdx - startIdx))])
            
            // Convert 8 bytes to bigint (will be ≤ 64 bits = 2^64 - 1)
            const chunkValue = decodeUint(byteArr)
            
            // Verify chunk is ≤ 64 bits (safety check)
            if (chunkValue >= BigInt(2) ** BigInt(64)) {
                throw new Error("String chunk exceeded 64 bits - this should never happen with 8-byte chunks")
            }

            // Use prepareIT (supports up to 128 bits, but our chunk is guaranteed ≤ 64 bits)
            const it = await this.#prepareIT(
                chunkValue,
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
     * Encrypts values up to 128 bits (uses #prepareIT)
     */
    async encryptValue(
        plaintextValue: bigint | number | string, 
        contractAddress: string, 
        functionSelector: string
    ): Promise<itUint | itString> {
        await this._ensureAesKey();
        
        const value = typeof plaintextValue === 'number' ? BigInt(plaintextValue) : plaintextValue

        if (typeof value === 'bigint') {
            const bitSize = value.toString(2).length
            
            if (bitSize > 128) {
                throw new Error("encryptValue: values larger than 128 bits are not supported");
            }
            
            return await this.#prepareIT(
                value,
                this._userOnboardInfo!.aesKey!,
                contractAddress,
                functionSelector
            );
        } else if (typeof value === 'string') {
            return await this.#buildStringInputText(
                value,
                this._userOnboardInfo!.aesKey!,
                contractAddress,
                functionSelector
            );
        } else {
            throw new Error("Unknown type");
        }
    }

    /**
     * Encrypts values up to 256 bits (uses #prepareIT256)
     */
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
        
        return await this.#prepareIT256(
            value,
            this._userOnboardInfo!.aesKey!,
            contractAddress,
            functionSelector
        );
    }

    /**
     * Decrypts ctUint256 ciphertexts (uses decryptUint256 from SDK)
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
            } else {
                throw new Error("user AES key is not defined and auto onboard is off.")
            }
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