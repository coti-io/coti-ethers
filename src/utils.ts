import { Contract, keccak256 } from "ethers";
import IAccountOnboard from "../abi/IAccountOnboard.json"
import { DEVNET_ONBOARD_CONTRACT_ADDRESS } from "./constants";
import { decryptRSA, generateRSAKeyPair, sign } from "./crypto";

export function getDefaultAccountOnboardContract(contractAddress: string) {
    return new Contract(contractAddress, IAccountOnboard)
}

export async function defaultOnboard(defaultOnboardContractAddress: string, privateKey: string) {
    const accountOnboardContract = getDefaultAccountOnboardContract(defaultOnboardContractAddress)

    const rsaKeyPair = generateRSAKeyPair()

    const signedEK = sign(keccak256(rsaKeyPair.publicKey), privateKey)

    const receipt = await (
        await accountOnboardContract
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