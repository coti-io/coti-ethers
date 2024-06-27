import {
    Provider,
    SigningKey,
    Wallet as BaseWallet,
} from 'ethers'
import { DEVNET_ONBOARD_CONTRACT_ADDRESS } from './constants'
import { defaultOnboard as defaultOnboardProcedure } from './utils'
import { decryptString, decryptUint, prepareStringIT, prepareUintIT } from './crypto'

export class Wallet extends BaseWallet {

    userKey: null | string | undefined

    constructor(privateKey: string | SigningKey, userKey?: null | string, provider?: null | Provider) {
        super(privateKey, provider)

        this.userKey = userKey
    }

    async defaultOnboard(defaultOnboardContractAddress = DEVNET_ONBOARD_CONTRACT_ADDRESS) {
        defaultOnboardProcedure(defaultOnboardContractAddress, this)
    }

    async encryptValue(plaintextValue: bigint | number | string, contractAddress: string, functionSelector: string) {
        if (this.userKey === null || this.userKey === undefined) {
            throw new Error('user AES key is not defined')
        }

        const value = typeof plaintextValue === 'number' ? BigInt(plaintextValue) : plaintextValue

        if (typeof value === 'bigint') {
            return prepareUintIT(value, { wallet: this, userKey: this.userKey }, contractAddress, functionSelector)
        } else if (typeof value === 'string') {
            return prepareStringIT(value, { wallet: this, userKey: this.userKey }, contractAddress, functionSelector)
        }
    }

    async decryptValue(ciphertext: bigint | Array<bigint>) {
        if (this.userKey === null || this.userKey === undefined) {
            throw new Error('user AES key is not defined')
        }

        if (typeof ciphertext === 'bigint') {
            return decryptUint(ciphertext, this.userKey)
        }

        return decryptString(ciphertext, this.userKey)
    }
}