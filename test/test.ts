import dotenv from "dotenv"

dotenv.config()

import * as coti_ethers from '../src'

async function test() {
    const privateKey = process.env.PRIVATE_KEY!
    const userKey = process.env.USER_KEY!

    const provider = new coti_ethers.JsonRpcProvider(coti_ethers.DEVNET_NODE_URL)

    const wallet = new coti_ethers.Wallet(privateKey, userKey, provider)

    await wallet.defaultOnboard()
}

test()