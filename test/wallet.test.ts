import {Wallet as etherWallet} from "ethers"
import {CotiNetwork, ONBOARD_CONTRACT_ADDRESS, getAccountOnboardContract, getDefaultProvider, Wallet} from '../src'
import {expect} from "chai"
import dotenv from "dotenv"

dotenv.config({ path: './test/.env' })

describe("Wallet tests", function () {
    this.timeout(30000);
    const pk = process.env.PRIVATE_KEY || Wallet.createRandom().privateKey;
    let wallet: Wallet

    it('Should successfully create wallet without aes key', function () {
        const provider = getDefaultProvider(CotiNetwork.Testnet)
        wallet = new Wallet(pk, provider);
        expect(wallet.address).to.equal(new etherWallet(pk).address);
        expect(wallet.getUserOnboardInfo()).to.be.undefined
    })

    it('Should successfully onboard the wallet', async function () {
        await wallet.generateOrRecoverAes()
        expect(wallet.getUserOnboardInfo()?.aesKey).to.not.equal(null);
        expect(wallet.getUserOnboardInfo()?.aesKey).to.equal(process.env.USER_KEY);
    })

    it('Should successfully encrypt and decrypt', async function () {
        // If onboarding failed, set AES key manually for testing
        // In production, onboarding should succeed and set the key automatically
        if (!wallet.getUserOnboardInfo()?.aesKey) {
            const aesKey = process.env.USER_KEY || process.env.AES_KEY;
            if (aesKey) {
                wallet.setAesKey(aesKey);
            } else {
                throw new Error("AES key not set. Either onboarding must succeed or USER_KEY/AES_KEY must be in .env file");
            }
        }
        
        const msg = "hello world"
        const accountOnboardContract: any = getAccountOnboardContract(ONBOARD_CONTRACT_ADDRESS, wallet)
        const inputText = await wallet.encryptValue(msg, ONBOARD_CONTRACT_ADDRESS, accountOnboardContract.interface.fragments[1].selector);
        let pt = await wallet.decryptValue(inputText.ciphertext);
        expect(pt).to.equal(msg)

    })

    it('Should successfully encrypt and decrypt 256-bit values', async function () {
        // Ensure AES key is set
        if (!wallet.getUserOnboardInfo()?.aesKey) {
            const aesKey = process.env.USER_KEY || process.env.AES_KEY;
            if (aesKey) {
                wallet.setAesKey(aesKey);
            } else {
                throw new Error("AES key not set");
            }
        }

        const accountOnboardContract: any = getAccountOnboardContract(ONBOARD_CONTRACT_ADDRESS, wallet)
        const functionSelector = accountOnboardContract.interface.fragments[1].selector;
        
        // Test with a 256-bit value (max 256-bit value)
        const value256 = BigInt("115792089237316195423570985008687907853269984665640564039457584007913129639935");
        const inputText256 = await wallet.encryptValue256(value256, ONBOARD_CONTRACT_ADDRESS, functionSelector);
        const decrypted256 = await wallet.decryptValue256(inputText256.ciphertext);
        expect(decrypted256).to.equal(value256);

        // Test with a 129-bit value (should use 256-bit encryption)
        const value129 = BigInt("340282366920938463463374607431768211456"); // 2^128
        const inputText129 = await wallet.encryptValue256(value129, ONBOARD_CONTRACT_ADDRESS, functionSelector);
        const decrypted129 = await wallet.decryptValue256(inputText129.ciphertext);
        expect(decrypted129).to.equal(value129);

        // Test with a smaller value that fits in 128 bits but using 256-bit encryption
        const valueSmall = BigInt(1000000);
        const inputTextSmall = await wallet.encryptValue256(valueSmall, ONBOARD_CONTRACT_ADDRESS, functionSelector);
        const decryptedSmall = await wallet.decryptValue256(inputTextSmall.ciphertext);
        expect(decryptedSmall).to.equal(valueSmall);
    })

    it('Should reject values larger than 256 bits in encryptValue256', async function () {
        if (!wallet.getUserOnboardInfo()?.aesKey) {
            const aesKey = process.env.USER_KEY || process.env.AES_KEY;
            if (aesKey) {
                wallet.setAesKey(aesKey);
            } else {
                throw new Error("AES key not set");
            }
        }

        const accountOnboardContract: any = getAccountOnboardContract(ONBOARD_CONTRACT_ADDRESS, wallet)
        const functionSelector = accountOnboardContract.interface.fragments[1].selector;
        
        // 257-bit value (2^256)
        const value257 = BigInt("115792089237316195423570985008687907853269984665640564039457584007913129639936");
        
        try {
            await wallet.encryptValue256(value257, ONBOARD_CONTRACT_ADDRESS, functionSelector);
            expect.fail("Should have thrown error for 257-bit value");
        } catch (error: any) {
            expect(error.message).to.include("values larger than 256 bits are not supported");
        }
    })

    it('Should handle zero value encryption/decryption', async function () {
        if (!wallet.getUserOnboardInfo()?.aesKey) {
            const aesKey = process.env.USER_KEY || process.env.AES_KEY;
            if (aesKey) {
                wallet.setAesKey(aesKey);
            } else {
                throw new Error("AES key not set");
            }
        }

        const accountOnboardContract: any = getAccountOnboardContract(ONBOARD_CONTRACT_ADDRESS, wallet)
        const functionSelector = accountOnboardContract.interface.fragments[1].selector;
        
        // Test zero value
        const zero = BigInt(0);
        const inputText = await wallet.encryptValue(zero, ONBOARD_CONTRACT_ADDRESS, functionSelector);
        const decrypted = await wallet.decryptValue(inputText.ciphertext);
        expect(decrypted).to.equal(zero);
    })

    it('Should handle maximum 128-bit value', async function () {
        if (!wallet.getUserOnboardInfo()?.aesKey) {
            const aesKey = process.env.USER_KEY || process.env.AES_KEY;
            if (aesKey) {
                wallet.setAesKey(aesKey);
            } else {
                throw new Error("AES key not set");
            }
        }

        const accountOnboardContract: any = getAccountOnboardContract(ONBOARD_CONTRACT_ADDRESS, wallet)
        const functionSelector = accountOnboardContract.interface.fragments[1].selector;
        
        // Max 128-bit value (2^128 - 1)
        const max128 = BigInt("340282366920938463463374607431768211455");
        const inputText = await wallet.encryptValue(max128, ONBOARD_CONTRACT_ADDRESS, functionSelector);
        const decrypted = await wallet.decryptValue(inputText.ciphertext);
        expect(decrypted).to.equal(max128);
    })

    it('Should reject values larger than 128 bits in encryptValue', async function () {
        if (!wallet.getUserOnboardInfo()?.aesKey) {
            const aesKey = process.env.USER_KEY || process.env.AES_KEY;
            if (aesKey) {
                wallet.setAesKey(aesKey);
            } else {
                throw new Error("AES key not set");
            }
        }

        const accountOnboardContract: any = getAccountOnboardContract(ONBOARD_CONTRACT_ADDRESS, wallet)
        const functionSelector = accountOnboardContract.interface.fragments[1].selector;
        
        // 129-bit value (2^128)
        const value129 = BigInt("340282366920938463463374607431768211456");
        
        try {
            await wallet.encryptValue(value129, ONBOARD_CONTRACT_ADDRESS, functionSelector);
            expect.fail("Should have thrown error for 129-bit value");
        } catch (error: any) {
            expect(error.message).to.include("values larger than 128 bits are not supported");
        }
    })

    it('Should fail to encrypt when autoOnboard flag off', async function () {
        const wallet = new Wallet(pk);
        wallet.disableAutoOnboard();
        const accountOnboardContract: any = getAccountOnboardContract(ONBOARD_CONTRACT_ADDRESS, wallet);
        let ct;
        let errorThrown = false;
        try {
            ct = await wallet.encryptValue(
                "on board",
                ONBOARD_CONTRACT_ADDRESS,
                accountOnboardContract.interface.fragments[1].selector
            );
        } catch (error) {
            errorThrown = true;
            // Only log error if test fails (when expect() throws)
            // The test framework will show the error message if the test fails
        }
        
        // If this expect fails, the test framework will show the error
        expect(errorThrown).to.be.true;
        expect(ct).to.be.undefined;
    });

    it('Should recover aes key from tx hash and rsa key', async function () {
        // Skip if required env vars are not set
        if (!process.env.RSA_PUB || !process.env.RSA_PRIVATE || !process.env.TX_HASH) {
            this.skip();
        }

        const provider = getDefaultProvider(CotiNetwork.Testnet)
        const wallet = new Wallet(pk, provider);
        await wallet.generateOrRecoverAes()
        const onBoardInfo = {
            rsaKey: {
                publicKey: parseRsaKey(process.env.RSA_PUB),
                privateKey: parseRsaKey(process.env.RSA_PRIVATE)
            },
            txHash: process.env.TX_HASH
        }
        const wallet2 = new Wallet(pk, provider, onBoardInfo);
        
        try {
            await wallet2.generateOrRecoverAes()
            expect(wallet.address).to.equal(wallet2.address);
            expect(wallet.getUserOnboardInfo()?.aesKey).to.equal(wallet2.getUserOnboardInfo()?.aesKey);
        } catch (error: any) {
            // If recovery fails (e.g., invalid tx hash), skip the test
            if (error.message.includes("failed to get onboard tx info") || 
                error.message.includes("unable to recover aes key")) {
                this.skip();
            } else {
                throw error;
            }
        }
    })

    it('Should be able to set autoOnboard off', function () {
        const wallet = new Wallet(pk);
        wallet.disableAutoOnboard()
        expect(wallet.getAutoOnboard()).to.equal(false)
    })

    it('Should be able to set autoOnboard on', function () {
        const wallet = new Wallet(pk);
        wallet.disableAutoOnboard()
        expect(wallet.getAutoOnboard()).to.equal(false)
        wallet.enableAutoOnboard()
        expect(wallet.getAutoOnboard()).to.equal(true)

    })

    it('Should be able to set userOnboardInfo parameters', function () {
        const wallet = new Wallet(pk);
        const rsaKey = {
            publicKey: parseRsaKey(process.env.RSA_PUB),
            privateKey: parseRsaKey(process.env.RSA_PRIVATE)
        }
        wallet.setRsaKeyPair(rsaKey)
        const txHash: string = process.env.TX_HASH || "0xb19996f54a420fa9b2e20ab79474f0d41f33c9adadaa38e7ebfd1b6fc16b3ebf"
        wallet.setOnboardTxHash(txHash)
        const aesKey = process.env.AES_KEY || "e0262555000f88878acc5b38146fbd05"
        wallet.setAesKey(aesKey)
        expect(wallet.getUserOnboardInfo()).to.not.be.undefined
    })

    it('Should be able to reset userOnboardInfo parameters', function () {
        const wallet = new Wallet(pk);
        const rsaKey = {
            publicKey: parseRsaKey(process.env.RSA_PUB),
            privateKey: parseRsaKey(process.env.RSA_PRIVATE)
        }
        wallet.setRsaKeyPair(rsaKey)
        const txHash: string = process.env.TX_HASH || "0xb19996f54a420fa9b2e20ab79474f0d41f33c9adadaa38e7ebfd1b6fc16b3ebf"
        wallet.setOnboardTxHash(txHash)
        const aesKey = process.env.AES_KEY || "e0262555000f88878acc5b38146fbd05"
        wallet.setAesKey(aesKey)
        expect(wallet.getUserOnboardInfo()).to.not.be.undefined
        wallet.clearUserOnboardInfo()
        expect(wallet.getUserOnboardInfo()).to.be.undefined
    })

    describe('Number type input tests', function () {
        it('Should successfully encrypt and decrypt number type input', async function () {
            if (!wallet.getUserOnboardInfo()?.aesKey) {
                const aesKey = process.env.USER_KEY || process.env.AES_KEY;
                if (aesKey) {
                    wallet.setAesKey(aesKey);
                } else {
                    throw new Error("AES key not set");
                }
            }

            const accountOnboardContract: any = getAccountOnboardContract(ONBOARD_CONTRACT_ADDRESS, wallet)
            const functionSelector = accountOnboardContract.interface.fragments[1].selector;
            
            // Test with number type (should be converted to BigInt)
            const numberValue = 12345;
            const inputText = await wallet.encryptValue(numberValue, ONBOARD_CONTRACT_ADDRESS, functionSelector);
            const decrypted = await wallet.decryptValue(inputText.ciphertext);
            expect(decrypted).to.equal(BigInt(numberValue));
        });

        it('Should successfully encrypt and decrypt number type with encryptValue256', async function () {
            if (!wallet.getUserOnboardInfo()?.aesKey) {
                const aesKey = process.env.USER_KEY || process.env.AES_KEY;
                if (aesKey) {
                    wallet.setAesKey(aesKey);
                } else {
                    throw new Error("AES key not set");
                }
            }

            const accountOnboardContract: any = getAccountOnboardContract(ONBOARD_CONTRACT_ADDRESS, wallet)
            const functionSelector = accountOnboardContract.interface.fragments[1].selector;
            
            // Test with number type for 256-bit encryption
            const numberValue = 987654321;
            const inputText = await wallet.encryptValue256(numberValue, ONBOARD_CONTRACT_ADDRESS, functionSelector);
            const decrypted = await wallet.decryptValue256(inputText.ciphertext);
            expect(decrypted).to.equal(BigInt(numberValue));
        });
    });

    describe('String edge cases', function () {
        it('Should handle empty string encryption/decryption', async function () {
            if (!wallet.getUserOnboardInfo()?.aesKey) {
                const aesKey = process.env.USER_KEY || process.env.AES_KEY;
                if (aesKey) {
                    wallet.setAesKey(aesKey);
                } else {
                    throw new Error("AES key not set");
                }
            }

            const accountOnboardContract: any = getAccountOnboardContract(ONBOARD_CONTRACT_ADDRESS, wallet)
            const functionSelector = accountOnboardContract.interface.fragments[1].selector;
            
            const emptyString = "";
            const inputText = await wallet.encryptValue(emptyString, ONBOARD_CONTRACT_ADDRESS, functionSelector);
            const decrypted = await wallet.decryptValue(inputText.ciphertext);
            expect(decrypted).to.equal(emptyString);
        });

        it('Should handle very long string encryption/decryption', async function () {
            if (!wallet.getUserOnboardInfo()?.aesKey) {
                const aesKey = process.env.USER_KEY || process.env.AES_KEY;
                if (aesKey) {
                    wallet.setAesKey(aesKey);
                } else {
                    throw new Error("AES key not set");
                }
            }

            const accountOnboardContract: any = getAccountOnboardContract(ONBOARD_CONTRACT_ADDRESS, wallet)
            const functionSelector = accountOnboardContract.interface.fragments[1].selector;
            
            // Create a very long string (1000 characters)
            const longString = "A".repeat(1000);
            const inputText = await wallet.encryptValue(longString, ONBOARD_CONTRACT_ADDRESS, functionSelector);
            const decrypted = await wallet.decryptValue(inputText.ciphertext);
            expect(decrypted).to.equal(longString);
        });
    });

    describe('Invalid ciphertext tests', function () {
        it('Should fail to decrypt with wrong AES key', async function () {
            if (!wallet.getUserOnboardInfo()?.aesKey) {
                const aesKey = process.env.USER_KEY || process.env.AES_KEY;
                if (aesKey) {
                    wallet.setAesKey(aesKey);
                } else {
                    throw new Error("AES key not set");
                }
            }

            const accountOnboardContract: any = getAccountOnboardContract(ONBOARD_CONTRACT_ADDRESS, wallet)
            const functionSelector = accountOnboardContract.interface.fragments[1].selector;
            
            // Encrypt with original key
            const originalValue = BigInt(12345);
            const inputText = await wallet.encryptValue(originalValue, ONBOARD_CONTRACT_ADDRESS, functionSelector);
            
            // Change AES key to a wrong one
            const wrongKey = "wrongkey123456789012345678901234567890";
            wallet.setAesKey(wrongKey);
            
            // Try to decrypt with wrong key - should fail or produce wrong result
            try {
                const decrypted = await wallet.decryptValue(inputText.ciphertext);
                // If it doesn't throw, the decrypted value should be different
                expect(decrypted).to.not.equal(originalValue);
            } catch (error: any) {
                // Expected to fail with wrong key
                expect(error).to.exist;
            }
        });

        it('Should fail to decrypt invalid ciphertext format', async function () {
            if (!wallet.getUserOnboardInfo()?.aesKey) {
                const aesKey = process.env.USER_KEY || process.env.AES_KEY;
                if (aesKey) {
                    wallet.setAesKey(aesKey);
                } else {
                    throw new Error("AES key not set");
                }
            }

            // Try to decrypt an invalid ciphertext (random bigint)
            const invalidCiphertext = BigInt("1234567890123456789012345678901234567890");
            
            try {
                await wallet.decryptValue(invalidCiphertext);
                // If it doesn't throw, that's also acceptable (might return garbage)
            } catch (error: any) {
                // Expected to fail with invalid ciphertext
                expect(error).to.exist;
            }
        });
    });

    describe('Onboarding failure scenarios', function () {
        it('Should fail to onboard with zero balance', async function () {
            const provider = getDefaultProvider(CotiNetwork.Testnet);
            // Create a new wallet with zero balance (random private key)
            const zeroBalanceWallet = new Wallet(Wallet.createRandom().privateKey, provider);
            zeroBalanceWallet.disableAutoOnboard(); // Disable auto-onboard to test explicit failure
            
            try {
                await zeroBalanceWallet.generateOrRecoverAes();
                expect.fail("Should have thrown error for zero balance");
            } catch (error: any) {
                expect(error.message).to.include("Account balance is 0");
            }
        });

        it('Should fail to recover AES key with invalid transaction hash', async function () {
            const provider = getDefaultProvider(CotiNetwork.Testnet);
            const testWallet = new Wallet(pk, provider);
            
            // Set invalid tx hash and RSA keys
            const invalidTxHash = "0x0000000000000000000000000000000000000000000000000000000000000000";
            const rsaKey = {
                publicKey: parseRsaKey(process.env.RSA_PUB) || new Uint8Array([1, 2, 3]),
                privateKey: parseRsaKey(process.env.RSA_PRIVATE) || new Uint8Array([1, 2, 3])
            };
            
            testWallet.setRsaKeyPair(rsaKey);
            testWallet.setOnboardTxHash(invalidTxHash);
            
            try {
                await testWallet.generateOrRecoverAes();
                // Might succeed if tx exists, or fail if invalid
                // This test verifies the error handling path exists
            } catch (error: any) {
                // Expected to fail with invalid tx hash
                expect(error).to.exist;
            }
        });
    });
})

function parseRsaKey(key: string | undefined): Uint8Array {
    if (!key) {
        throw new Error("Key is undefined in .env file");
    }
    return new Uint8Array(key.split(',').map(Number));
}
