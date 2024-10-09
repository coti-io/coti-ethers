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
        const msg = "hello world"
        const accountOnboardContract: any = getAccountOnboardContract(ONBOARD_CONTRACT_ADDRESS, wallet)
        const inputText = await wallet.encryptValue(msg, ONBOARD_CONTRACT_ADDRESS, accountOnboardContract.interface.fragments[1].selector);
        let pt = await wallet.decryptValue(inputText.ciphertext);
        expect(pt).to.equal(msg)

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
            console.error("An error occurred:", error);
        }
        expect(errorThrown).to.be.true;
        expect(ct).to.be.undefined;
    });

    it('Should recover aes key from tx hash and rsa key', async function () {
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
        await wallet2.generateOrRecoverAes()
        expect(wallet.address).to.equal(wallet2.address);
        expect(wallet.getUserOnboardInfo()?.aesKey).to.equal(wallet2.getUserOnboardInfo()?.aesKey);
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
})

function parseRsaKey(key: string | undefined): Uint8Array {
    if (!key) {
        throw new Error("Key is undefined in .env file");
    }
    return new Uint8Array(key.split(',').map(Number));
}
