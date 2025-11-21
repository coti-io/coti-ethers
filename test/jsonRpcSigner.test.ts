import { BrowserProvider } from '../src/providers/BrowserProvider';
import { JsonRpcSigner } from '../src/providers/JsonRpcSigner';
import { itUint, itUint256, itString } from '@coti-io/coti-sdk-typescript';
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
    const value128 = BigInt("340282366920938463463374607431768211455");
    const value256 = BigInt("115792089237316195423570985008687907853269984665640564039457584007913129639935");
    const valueString = "Hello COTI!";
    
    console.log("=".repeat(60));
    console.log("ENCRYPTION TESTS");
    console.log("=".repeat(60));
    
    console.log("\n1. Testing 64-bit encryption...");
    const encrypted64Result = await signer.encryptValue(value64, contractAddress, functionSelector);
    const encrypted64 = encrypted64Result as itUint;
    console.log("✅ 64-bit encrypted:", encrypted64.ciphertext);
    
    console.log("\n2. Testing 128-bit encryption...");
    const encrypted128Result = await signer.encryptValue(value128, contractAddress, functionSelector);
    const encrypted128 = encrypted128Result as itUint;
    console.log("✅ 128-bit encrypted:", encrypted128.ciphertext);
    
    console.log("\n3. Testing 256-bit encryption...");
    const encrypted256Result = await signer.encryptValue(value256, contractAddress, functionSelector);
    const encrypted256 = encrypted256Result as itUint256;
    console.log("✅ 256-bit encrypted:");
    console.log("   High:", encrypted256.ciphertext.ciphertextHigh);
    console.log("   Low:", encrypted256.ciphertext.ciphertextLow);
    
    console.log("\n4. Testing string encryption...");
    const encryptedStringResult = await signer.encryptValue(valueString, contractAddress, functionSelector);
    const encryptedString = encryptedStringResult as itString;
    console.log("✅ String encrypted:", encryptedString.ciphertext.value.length, "chunks");
    
    console.log("\n" + "=".repeat(60));
    console.log("DECRYPTION TESTS");
    console.log("=".repeat(60));
    
    console.log("\n5. Testing 64-bit decryption...");
    const decrypted64 = await signer.decryptValue(encrypted64.ciphertext);
    console.log("   Original:", value64);
    console.log("   Decrypted:", decrypted64);
    if (decrypted64 === value64) {
        console.log("✅ 64-bit decryption: PASSED");
    } else {
        console.log("❌ 64-bit decryption: FAILED");
        throw new Error(`64-bit mismatch: expected ${value64}, got ${decrypted64}`);
    }
    
    console.log("\n6. Testing 128-bit decryption...");
    const decrypted128 = await signer.decryptValue(encrypted128.ciphertext);
    console.log("   Original:", value128);
    console.log("   Decrypted:", decrypted128);
    if (decrypted128 === value128) {
        console.log("✅ 128-bit decryption: PASSED");
    } else {
        console.log("❌ 128-bit decryption: FAILED");
        throw new Error(`128-bit mismatch: expected ${value128}, got ${decrypted128}`);
    }
    
    console.log("\n7. Testing 256-bit decryption...");
    const decrypted256 = await signer.decryptValue(encrypted256.ciphertext);
    console.log("   Original:", value256);
    console.log("   Decrypted:", decrypted256);
    if (decrypted256 === value256) {
        console.log("✅ 256-bit decryption: PASSED");
    } else {
        console.log("❌ 256-bit decryption: FAILED");
        throw new Error(`256-bit mismatch: expected ${value256}, got ${decrypted256}`);
    }
    
    console.log("\n8. Testing string decryption...");
    const decryptedString = await signer.decryptValue(encryptedString.ciphertext);
    console.log("   Original:", `"${valueString}"`);
    console.log("   Decrypted:", `"${decryptedString}"`);
    if (decryptedString === valueString) {
        console.log("✅ String decryption: PASSED");
    } else {
        console.log("❌ String decryption: FAILED");
        throw new Error(`String mismatch: expected "${valueString}", got "${decryptedString}"`);
    }
    
    console.log("\n" + "=".repeat(60));
    console.log("✅ ALL TESTS PASSED!");
    console.log("=".repeat(60));
}

test().catch(console.error);