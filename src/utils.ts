import { Contract, keccak256 } from "ethers";
import IAccountOnboard from "../abi/IAccountOnboard.json"
import { decryptRSA, generateRSAKeyPair, sign } from "@coti-io/coti-sdk-typescript";
import { Wallet } from "./wallet";

export function getDefaultAccountOnboardContract(contractAddress: string) {
    return new Contract(contractAddress, IAccountOnboard)
}

export async function defaultOnboard(defaultOnboardContractAddress: string, wallet: Wallet) {
    const accountOnboardContract: any = getDefaultAccountOnboardContract(defaultOnboardContractAddress)

    const rsaKeyPair = generateRSAKeyPair()

    const prefix = Buffer.from("\x19Ethereum Signed Message:\n")
    const messageLength = Buffer.from(rsaKeyPair.publicKey.length.toString())
    const message = rsaKeyPair.publicKey

    // sign using EIP-191 format
    const signedEK = sign(keccak256(Buffer.concat([prefix, messageLength, message])), wallet.privateKey)
    signedEK[signedEK.length - 1] = 27

    const tx = await accountOnboardContract
        .connect(wallet)
        .OnboardAccount(
            rsaKeyPair.publicKey,
            signedEK,
            { gasLimit: 12000000 }
        )
    
    const receipt = await tx.wait()

    if (!receipt || !receipt.logs || !receipt.logs[0]) {
        throw new Error("failed to onboard account")
    }

    const decodedLog = accountOnboardContract.interface.parseLog(receipt.logs[0])

    if (!decodedLog) {
        throw new Error("failed to onboard account")
    }

    const encryptedKey = decodedLog.args.userKey

    const buf = Buffer.from(encryptedKey.substring(2), "hex")

    return decryptRSA(rsaKeyPair.privateKey, buf)
}

// TypeScript SDK
// 0x00c9a235d20f4e017c71052f382816a21448abc2bd3ff2fe68912767b1153ee0064220bcd7ddfac0f3623b3b36260a808157bfab99ded0ee727c0793fc107b0500

// Remix Plugin
// 0x5e160f8484d913c4103737c6e8756b3f3a86b7a46a8efb4a8d36bc939c6f88853f8d5fddfe4afa8b94aa45c0a449e014a7dcd5bb097cc58b9dc74185ec6f54f11c