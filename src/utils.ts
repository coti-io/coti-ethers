import {BaseWallet, Contract, keccak256, Signer} from "ethers";
import {decryptRSA, generateRSAKeyPair, initEtherProvider, sign} from "@coti-io/coti-sdk-typescript";
import {RsaKeyPair} from "./types";
import {ONBOARD_CONTRACT_ABI} from "./constants";

export function getAccountOnboardContract(contractAddress: string, wallet?: Signer) {
    return new Contract(contractAddress, JSON.stringify(ONBOARD_CONTRACT_ABI), wallet)
}


export async function onboard(defaultOnboardContractAddress: string, wallet: BaseWallet) {
    try {
        const accountOnboardContract: any = getAccountOnboardContract(defaultOnboardContractAddress, wallet)
        const {publicKey, privateKey} = generateRSAKeyPair()

        let receipt;
        const signedEK = sign(keccak256(publicKey), wallet.privateKey)
        receipt = await (await accountOnboardContract.onboardAccount(publicKey, signedEK, {gasLimit: 12000000})).wait()

        if (!receipt || !receipt.logs || !receipt.logs[0]) {
            throw new Error("failed to onboard account")
        }
        const decodedLog = accountOnboardContract.interface.parseLog(receipt.logs[0])
        if (!decodedLog) {
            throw new Error("failed to onboard account")
        }
        const encryptedKey = decodedLog.args.userKey
        console.log(encryptedKey)
        return {
            aesKey: decryptRSA(privateKey, encryptedKey.substring(2)),
            rsaKey: {publicKey: publicKey, privateKey: privateKey},
            txHash: receipt.hash
        }
    } catch (e) {
        console.error("unable to onboard user.")
        throw Error(`unable to onboard user.`)
    }

}


export async function recoverAesFromTx(txHash: string,
                                       rsaKey: RsaKeyPair,
                                       defaultOnboardContractAddress: string,
                                       wallet: BaseWallet) {
    try {
        const receipt = wallet.provider
            ? await wallet.provider.getTransactionReceipt(txHash)
            : await initEtherProvider().getTransactionReceipt(txHash);

        if (!receipt || !receipt.logs || !receipt.logs[0]) {
            console.error("failed to get onboard tx info")
            throw new Error("failed to get onboard tx info")
        }

        const accountOnboardContract: any = getAccountOnboardContract(defaultOnboardContractAddress)
        const decodedLog = accountOnboardContract.interface.parseLog(receipt.logs[0])
        const encryptedKey = decodedLog.args.userKey
        return decryptRSA(rsaKey.privateKey, encryptedKey.substring(2))
    } catch (e) {
        console.error("failed to get onboard tx info")
        throw Error(`unable to recover aes key from transaction.`)
    }

}
