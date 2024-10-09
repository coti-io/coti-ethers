import { Contract, ContractRunner, keccak256, Provider } from "ethers"
import { getDefaultProvider } from "./network"
import { decryptRSA, generateRSAKeyPair, recoverUserKey, sign } from "@coti-io/coti-sdk-typescript"
import { CotiNetwork, RsaKeyPair } from "../types"
import { ONBOARD_CONTRACT_ABI } from "./constants"
import { Wallet } from "../wallet/Wallet"
import { JsonRpcSigner } from "../providers/JsonRpcSigner"

export function getAccountOnboardContract(contractAddress: string, runner?: ContractRunner) {
    return new Contract(contractAddress, JSON.stringify(ONBOARD_CONTRACT_ABI), runner)
}

export async function onboard(defaultOnboardContractAddress: string, signer: Wallet | JsonRpcSigner) {
    try {
        const accountOnboardContract: any = getAccountOnboardContract(defaultOnboardContractAddress, signer)
        const {publicKey, privateKey} = generateRSAKeyPair()

        let signedEK: string | Uint8Array

        if (signer instanceof Wallet) {
            signedEK = sign(keccak256(publicKey), signer.privateKey)
        } else {
            signedEK = await signer.signMessage(publicKey)
        }

        const receipt = await (await accountOnboardContract.onboardAccount(publicKey, signedEK, {gasLimit: 12000000})).wait()

        if (!receipt || !receipt.logs || !receipt.logs[0]) {
            throw new Error("failed to onboard account")
        }
        const decodedLog = accountOnboardContract.interface.parseLog(receipt.logs[0])
        if (!decodedLog) {
            throw new Error("failed to onboard account")
        }

        const userKey1 = decodedLog.args.userKey1.substring(2);
        const userKey2 = decodedLog.args.userKey2.substring(2);
        
        return {
            aesKey: recoverUserKey(privateKey, userKey1, userKey2),
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
                                       provider: Provider | null) {
    try {
        const receipt = provider
            ? await provider.getTransactionReceipt(txHash)
            : await getDefaultProvider(CotiNetwork.Testnet).getTransactionReceipt(txHash)

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