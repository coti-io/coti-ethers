export enum CotiNetwork {
    Testnet = 'https://testnet.coti.io/rpc',
    Mainnet = 'https://mainnet.coti.io/rpc'
}

export type OnboardInfo = {
    aesKey?: string | null | undefined;
    rsaKey?: RsaKeyPair | null | undefined;
    txHash?: string | null | undefined;
}

export type RsaKeyPair = {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
}
