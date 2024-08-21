import {Wallet as etherWallet} from "ethers"
import {DEVNET_ONBOARD_CONTRACT_ADDRESS, getAccountOnboardContract, Wallet} from '../src'
import {expect} from "chai"
import 'dotenv/config';


describe("Wallet tests", async function () {
    this.timeout(20000);
    const pk = process.env.PRIVATE_KEY || Wallet.createRandom().privateKey;

    it('Should successfully create wallet without aes key', async function () {
        const wallet = new Wallet(pk);
        expect(wallet.address).to.equal(new etherWallet(pk).address);
        expect(wallet.getUserOnboardInfo()).to.be.null
    })

    it('Should successfully create wallet and onboard it.', async function () {
        const wallet = new Wallet(pk);
        await wallet.generateOrRecoverAes()
        expect(wallet.address).to.equal(new etherWallet(pk).address);
        expect(wallet.getUserOnboardInfo()?.aesKey).to.not.equal(null);
        expect(wallet.getUserOnboardInfo()?.aesKey).to.equal(process.env.AES_KEY);
    })

    it('Should successfully encrypt and decrypt', async function () {
        const msg = "hello world"
        const wallet = new Wallet(pk);
        await wallet.generateOrRecoverAes()
        const accountOnboardContract: any = getAccountOnboardContract(DEVNET_ONBOARD_CONTRACT_ADDRESS, wallet)
        // const func = accountOnboardContract.fragment.onboard
        const ct: { ctInt: bigint; signature: Uint8Array; } | {
            ciphertext: bigint,
            signature: Uint8Array
        }[] = await wallet.encryptValue(msg, DEVNET_ONBOARD_CONTRACT_ADDRESS, accountOnboardContract.interface.fragments[1].selector);
        let pt
        const ciphertexts = ct.map((val) => val.ciphertext);
        pt = await wallet.decryptValue(ciphertexts);
        expect(ciphertexts[0]).to.not.equal(msg[0])
        expect(pt).to.equal(msg)

    })

    it('Should failed encrypt when autoOnboard flag off', async function () {
        const wallet = new Wallet(pk);
        wallet.disableAutoOnboard();
        const accountOnboardContract: any = getAccountOnboardContract(DEVNET_ONBOARD_CONTRACT_ADDRESS, wallet);
        let ct;
        let errorThrown = false;
        try {
            ct = await wallet.encryptValue(
                "on board",
                DEVNET_ONBOARD_CONTRACT_ADDRESS,
                accountOnboardContract.interface.fragments[1].selector
            );
        } catch (error) {
            errorThrown = true;
            console.error("An error occurred:", error);
        }
        expect(errorThrown).to.be.true;
        expect(ct).to.be.undefined;
    });

    it('Should aes recovered from tx hash and rsa key', async function () {
        const wallet = new Wallet(pk);
        await wallet.generateOrRecoverAes()
        const onBoardInfo = {
            rsaKey: {
                publicKey: parseRsaKey(process.env.RSA_PUB),
                privateKey: parseRsaKey(process.env.RSA_PRIVATE)
            },
            txHash: process.env.TX_HASH
        }
        const wallet2 = new Wallet(pk, null, onBoardInfo);
        await wallet2.generateOrRecoverAes()
        expect(wallet.address).to.equal(wallet2.address);
        expect(wallet.getUserOnboardInfo()?.aesKey).to.equal(wallet2.getUserOnboardInfo()?.aesKey);
    })

    it('Should be able to set autoOnboard off', async function () {
        const wallet = new Wallet(pk);
        wallet.disableAutoOnboard()
        expect(wallet.getAutoOnboard()).to.equal(false)
    })

    it('Should be able to set autoOnboard on', async function () {
        const wallet = new Wallet(pk);
        wallet.disableAutoOnboard()
        expect(wallet.getAutoOnboard()).to.equal(false)
        wallet.enableAutoOnboard()
        expect(wallet.getAutoOnboard()).to.equal(true)

    })

    it('Should be able to set userOnboardInfo parameters.', async function () {
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
        expect(wallet.getUserOnboardInfo()).to.not.be.null
    })

    it('Should be able to reset userOnboardInfo parameters.', async function () {
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
        expect(wallet.getUserOnboardInfo()).to.not.be.null
        wallet.clearUserOnboardInfo()
        expect(wallet.getUserOnboardInfo()).to.be.null
    })
})

function parseRsaKey(key: string | undefined): Uint8Array {
    if (!key) {
        throw new Error("Key is undefined in .env file");
    }
    return new Uint8Array(key.split(',').map(Number));
}
