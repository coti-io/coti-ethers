import { Contract, keccak256 } from "ethers";
import IAccountOnboard from "../abi/IAccountOnboard.json"
import { decryptRSA, generateRSAKeyPair, sign } from "./crypto";
import { Wallet } from "./wallet";

export function getDefaultAccountOnboardContract(contractAddress: string) {
    return new Contract(contractAddress, IAccountOnboard)
}

export async function defaultOnboard(defaultOnboardContractAddress: string, wallet: Wallet) {
    const accountOnboardContract: any = getDefaultAccountOnboardContract(defaultOnboardContractAddress)

    const rsaKeyPair = generateRSAKeyPair()

    const signedEK = sign(keccak256(rsaKeyPair.publicKey), wallet.privateKey)

    const receipt = await (
        await accountOnboardContract
            .connect(wallet)
            .OnboardAccount(
                rsaKeyPair.publicKey,
                signedEK,
                { gasLimit: 12000000 }
            )
        ).wait()

    if (!receipt || !receipt.logs || !receipt.logs[0]) {
        throw new Error("failed to onboard account")
    }

    const decodedLog = accountOnboardContract.interface.parseLog(receipt.logs[0])

    if (!decodedLog) {
        throw new Error("failed to onboard account")
    }

    const encryptedKey = decodedLog.args.userKey

    const buf = Buffer.from(encryptedKey.substring(2), "hex")

    return decryptRSA(rsaKeyPair.privateKey, buf).toString("hex")
}