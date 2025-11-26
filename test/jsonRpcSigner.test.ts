import { BrowserProvider } from '../src/providers/BrowserProvider';
import { JsonRpcSigner } from '../src/providers/JsonRpcSigner';
import { itUint, itUint256, itString, ctUint256 } from '@coti-io/coti-sdk-typescript';
import dotenv from "dotenv";

// Load environment variables
dotenv.config({ path: './test/.env' });

// Mock window.ethereum for Node.js testing
class MockEthereum {
    accounts: string[];
    
    constructor(accountAddress: string) {
        this.accounts = [accountAddress];
    }
    
    async request(payload: { method: string; params?: any[] }) {
        if (payload.method === "eth_requestAccounts" || payload.method === "eth_accounts") {
            return this.accounts;
        }
        if (payload.method === "eth_chainId") {
            return "0x1";
        }
        if (payload.method === "personal_sign") {
            // Mock signature
            return "0x" + "1".repeat(130);
        }
        throw new Error(`Method ${payload.method} not implemented`);
    }
}

// Helper function to reduce code duplication
async function testEncryptionDecryption(
    name: string,
    originalValue: bigint | string,
    signer: JsonRpcSigner,
    contractAddress: string,
    functionSelector: string,
    use256Bit: boolean = false
): Promise<void> {
    console.log(`\n${name}...`);
    
    // Encrypt
    let encrypted: itUint | itUint256 | itString;
    if (use256Bit && typeof originalValue === 'bigint') {
        encrypted = await signer.encryptValue256(originalValue, contractAddress, functionSelector);
        const encrypted256 = encrypted as itUint256;
        console.log(`✅ ${name} encrypted:`);
        console.log(`   High: ${encrypted256.ciphertext.ciphertextHigh}`);
        console.log(`   Low: ${encrypted256.ciphertext.ciphertextLow}`);
    } else {
        encrypted = await signer.encryptValue(originalValue, contractAddress, functionSelector);
        if (typeof originalValue === 'string') {
            const encryptedString = encrypted as itString;
            console.log(`✅ ${name} encrypted: ${encryptedString.ciphertext.value.length} chunks`);
        } else {
            const encryptedUint = encrypted as itUint;
            console.log(`✅ ${name} encrypted: ${encryptedUint.ciphertext}`);
        }
    }
    
    // Decrypt
    let decrypted: bigint | string;
    if (use256Bit && typeof originalValue === 'bigint') {
        const encrypted256 = encrypted as itUint256;
        decrypted = await signer.decryptValue256({
            ciphertextHigh: encrypted256.ciphertext.ciphertextHigh,
            ciphertextLow: encrypted256.ciphertext.ciphertextLow
        } as ctUint256);
    } else {
        if (typeof originalValue === 'string') {
            const encryptedString = encrypted as itString;
            decrypted = await signer.decryptValue(encryptedString.ciphertext);
        } else {
            const encryptedUint = encrypted as itUint;
            decrypted = await signer.decryptValue(encryptedUint.ciphertext);
        }
    }
    
    // Verify
    console.log(`   Original: ${typeof originalValue === 'string' ? `"${originalValue}"` : originalValue.toString()}`);
    console.log(`   Decrypted: ${typeof decrypted === 'string' ? `"${decrypted}"` : decrypted.toString()}`);
    
    if (decrypted === originalValue) {
        console.log(`✅ ${name}: PASSED`);
    } else {
        console.log(`❌ ${name}: FAILED`);
        throw new Error(`${name} mismatch: expected ${originalValue}, got ${decrypted}`);
    }
}

async function test() {
    // Get account address from .env file (browser-based, no Wallet needed)
    const accountAddress = process.env.ACCOUNT_ADDRESS || process.env.PUBLIC_KEY;
    
    // Get AES key from .env file
    const aesKey = process.env.USER_KEY;
    
    if (!accountAddress) {
        throw new Error("ACCOUNT_ADDRESS or PUBLIC_KEY must be set in .env file");
    }
    
    if (!aesKey) {
        throw new Error("USER_KEY must be set in .env file");
    }
    
    console.log(`Using account: ${accountAddress}`);
    console.log(`Using AES key: ${aesKey.substring(0, 10)}...`);
    
    // Use the accountAddress from .env
    const mockEthereum = new MockEthereum(accountAddress);
    const provider = new BrowserProvider(mockEthereum as any);
    const signer = await provider.getSigner();
    
    // Set AES key from .env file
    signer.setAesKey(aesKey);
    
    const contractAddress = "0x1234567890123456789012345678901234567890";
    const functionSelector = "0x12345678";
    
    // Test values
    const value64 = BigInt(1000000);
    const value128 = BigInt("340282366920938463463374607431768211455"); // Max 128-bit
    const value256 = BigInt("115792089237316195423570985008687907853269984665640564039457584007913129639935"); // Max 256-bit
    const valueString = "Hello COTI!";
    
    console.log("=".repeat(60));
    console.log("ENCRYPTION/DECRYPTION TESTS");
    console.log("=".repeat(60));
    
    // Test 64-bit value (uses encryptValue)
    await testEncryptionDecryption(
        "1. Testing 64-bit encryption/decryption",
        value64,
        signer,
        contractAddress,
        functionSelector,
        false
    );
    
    // Test 128-bit value (uses encryptValue)
    await testEncryptionDecryption(
        "2. Testing 128-bit encryption/decryption",
        value128,
        signer,
        contractAddress,
        functionSelector,
        false
    );
    
    // Test 256-bit value (uses encryptValue256)
    await testEncryptionDecryption(
        "3. Testing 256-bit encryption/decryption",
        value256,
        signer,
        contractAddress,
        functionSelector,
        true
    );
    
    // Test string (uses encryptValue)
    await testEncryptionDecryption(
        "4. Testing string encryption/decryption",
        valueString,
        signer,
        contractAddress,
        functionSelector,
        false
    );
    
    // Test error cases
    console.log("\n" + "=".repeat(60));
    console.log("ERROR HANDLING TESTS");
    console.log("=".repeat(60));
    
    // Test 129-bit value should fail with encryptValue
    console.log("\n5. Testing 129-bit value rejection (encryptValue)...");
    const value129 = 2n ** 128n; // 129-bit value
    try {
        await signer.encryptValue(value129, contractAddress, functionSelector);
        console.log("❌ Should have thrown error for 129-bit value");
        throw new Error("encryptValue should reject values > 128 bits");
    } catch (error: any) {
        if (error.message.includes("values larger than 128 bits are not supported")) {
            console.log("✅ Correctly rejected 129-bit value");
        } else {
            throw error;
        }
    }
    
    // Test 257-bit value should fail with encryptValue256
    console.log("\n6. Testing 257-bit value rejection (encryptValue256)...");
    const value257 = 2n ** 256n; // 257-bit value
    try {
        await signer.encryptValue256(value257, contractAddress, functionSelector);
        console.log("❌ Should have thrown error for 257-bit value");
        throw new Error("encryptValue256 should reject values > 256 bits");
    } catch (error: any) {
        if (error.message.includes("values larger than 256 bits are not supported")) {
            console.log("✅ Correctly rejected 257-bit value");
        } else {
            throw error;
        }
    }
    
    console.log("\n" + "=".repeat(60));
    console.log("✅ ALL TESTS PASSED!");
    console.log("=".repeat(60));
}

test().catch(console.error);


