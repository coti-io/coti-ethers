# coti-ethers

In order to provide easy access to all the features of COTI, the coti-ethers JavaScript SDK was created, which is made in a way that has an interface very similar to those of ethers. In fact, ethers is a peer dependency of our library and all of the objects exported by coti-ethers ( e.g. Wallet, BrowserProvider, etc.) inherit from the corresponding ethers objects and extend their functionality where needed.

While most of the existing SDKs should work out of the box, using unique COTI features like encrypting transaction inputs, requires executing the onboarding procedure and encrypting using the defined protocol.

The library is made in such a way that after replacing ethers with coti-ethers most client apps will work out of box.

# `BrowserProvider` Class

The `BrowserProvider` class extends the `JsonRpcApiPollingProvider` and provides an interface for interacting with an EIP-1193 compatible browser provider (such as MetaMask). This class enables the sending of JSON-RPC requests to Ethereum nodes via browser extensions and handles account management and signer creation.

## **Constructor**

```typescript
constructor(ethereum: Eip1193Provider, network?: Networkish, _options?: BrowserProviderOptions)
```

- **Parameters**:
  - `ethereum`: An `Eip1193Provider` (typically a browser extension like MetaMask) that implements the `request` method for sending JSON-RPC requests.
  - `network?`: Optional. A `Networkish` object representing the network configuration (e.g., mainnet, testnet).
  - `_options?`: Optional. `BrowserProviderOptions` that are merged into the `JsonRpcApiProviderOptions` for additional configuration.

- **Description**: Initializes the `BrowserProvider` by setting up the underlying provider and validating the `ethereum` object. It sets the default configuration for handling JSON-RPC requests and provides error handling and debugging features.

- **Throws**:
  - An error if the provided `ethereum` object is not a valid EIP-1193 provider.

## **Private Fields**

### **`#request`**

- **Type**: `(method: string, params: Array<any> | Record<string, any>) => Promise<any>`
  
- **Description**: A private method used to send EIP-1193 JSON-RPC requests to the Ethereum provider. This method emits debugging information about the request and handles errors by attaching the error code, data, and payload for better error management.

## **Public Methods**

### 1. **`send(method: string, params: Array<any> | Record<string, any>): Promise<any>`**

- **Parameters**:
  - `method`: A string representing the JSON-RPC method (e.g., `eth_accounts`, `eth_sendTransaction`).
  - `params`: An array or object containing the parameters for the JSON-RPC method.

- **Returns**: A `Promise<any>` resolving to the result of the JSON-RPC method.

- **Description**: Sends a JSON-RPC request to the Ethereum provider using the inherited `send` method after initializing the provider via `_start()`.

### 2. **`_send(payload: JsonRpcPayload | Array<JsonRpcPayload>): Promise<Array<JsonRpcResult | JsonRpcError>>`**

- **Parameters**:
  - `payload`: A `JsonRpcPayload` object or an array of such objects representing the JSON-RPC request(s).

- **Returns**: A `Promise<Array<JsonRpcResult | JsonRpcError>>`, resolving to an array containing the results or errors from the JSON-RPC request.

- **Description**: Sends a single JSON-RPC request using the EIP-1193 protocol. This method does not support batch requests as EIP-1193 does not allow them. If an error occurs, the method returns the error details including the code, message, and data.

- **Throws**: Throws an error if batch requests are attempted.

### 3. **`getRpcError(payload: JsonRpcPayload, error: JsonRpcError): Error`**

- **Parameters**:
  - `payload`: The original JSON-RPC payload that triggered the error.
  - `error`: A `JsonRpcError` object containing error details such as the error code, message, and data.

- **Returns**: An `Error` object with additional information based on the error code.

- **Description**: Enhances the error message based on known EIP-1193 error codes. For example, it rewrites the error message for:
  - `4001`: User denied the request.
  - `4200`: Unsupported request.
  
- **Example**:
  - `4001` becomes `ethers-user-denied: {message}`
  - `4200` becomes `ethers-unsupported: {message}`

### 4. **`hasSigner(address: number | string): Promise<boolean>`**

- **Parameters**:
  - `address`: A `number` (account index) or `string` (Ethereum address).

- **Returns**: A `Promise<boolean>`, resolving to `true` if the provider manages the given address.

- **Description**: Checks if the provider manages the given account. If an account index is passed, it checks if the account exists at that index. If an address is passed, it verifies whether the address is managed by the provider.

- **Example**:
  ```typescript
  const isSigner = await provider.hasSigner("0xYourAddress");
  ```

### 5. **`getSigner(address?: number | string, userOnboardInfo?: OnboardInfo): Promise<JsonRpcSigner>`**

- **Parameters**:
  - `address?`: An optional `number` or `string` representing the account index or Ethereum address. Defaults to the first account if not provided.
  - `userOnboardInfo?`: Optional `OnboardInfo` object containing user-specific data such as AES keys and RSA key pairs for the signer.

- **Returns**: A `Promise<JsonRpcSigner>`, resolving to a custom `JsonRpcSigner` instance associated with the given address.

- **Description**: Retrieves the `JsonRpcSigner` for the specified account. If the provider doesn't manage the specified account, it triggers a request to the Ethereum provider to access accounts (e.g., MetaMask's `eth_requestAccounts` method). After confirming account access, it returns the signer.

## **Private Methods**

### **`#request`**

- **Type**: `(method: string, params: Array<any> | Record<string, any>) => Promise<any>`

- **Description**: This method sends JSON-RPC requests to the Ethereum provider via EIP-1193. It emits debugging information for requests and responses and includes enhanced error handling by augmenting errors with additional metadata such as code and data.

## **Error Handling**

- **Batch Request Errors**: The class does not support batch JSON-RPC requests. Attempting to send a batch will throw an error.
  
- **EIP-1193 Error Codes**: Custom error handling is provided for common EIP-1193 errors such as:
  - `4001`: User denied the request.
  - `4200`: Unsupported request.
  
  These errors are intercepted and rewritten into more descriptive messages before being thrown.

## Example Usage

```typescript
import { BrowserProvider } from "./BrowserProvider";
import { JsonRpcSigner } from "./JsonRpcSigner";
import { Eip1193Provider } from "ethers";

// Example: Connect to MetaMask provider and retrieve the signer
const ethereumProvider = window.ethereum as Eip1193Provider;
const provider = new BrowserProvider(ethereumProvider);

// Retrieve the signer for the first account
const signer: JsonRpcSigner = await provider.getSigner(0);

// Send a request using the provider
const blockNumber = await provider.send("eth_blockNumber", []);
console.log("Current Block Number:", blockNumber);

// Check if an account is managed by the provider
const hasSigner = await provider.hasSigner("0xYourEthereumAddress");
console.log("Has Signer:", hasSigner);
```

# `JsonRpcApiProvider` Class

The `JsonRpcApiProvider` class extends the base `JsonRpcApiProvider` from the `ethers.js` library. It adds custom functionality for interacting with JSON-RPC APIs and provides an implementation for retrieving a `JsonRpcSigner`, which includes onboarding user information in the Coti network.

## **Constructor**

```typescript
constructor(network?: Networkish, options?: JsonRpcApiProviderOptions)
```

- **Parameters**:
  - `network?`: An optional `Networkish` object that specifies the network to connect to.
  - `options?`: Optional configuration options for the JSON-RPC provider (of type `JsonRpcApiProviderOptions`).

- **Description**: Initializes a new instance of the `JsonRpcApiProvider` class. It extends the base provider from `ethers.js`, allowing additional functionality for managing signers and user-specific onboarding.

## **Public Methods**

### 1. **`getSigner(address?: number | string, userOnboardInfo?: OnboardInfo): Promise<JsonRpcSigner>`**

- **Parameters**:
  - `address?`: An optional `number` or `string` that specifies which account to use. If not provided, defaults to the first account (`0`).
    - If a `number` is provided, it refers to the account index.
    - If a `string` is provided, it refers to an Ethereum address.
  - `userOnboardInfo?`: Optional `OnboardInfo` object that contains user-specific information, such as AES keys, RSA keys, and transaction hashes.

- **Returns**: A `Promise<JsonRpcSigner>`, resolving to a custom `JsonRpcSigner` instance associated with the given account.

- **Description**: This method retrieves a `JsonRpcSigner` instance for the specified account. The method handles two cases:
  1. **Account Index**: If the `address` is a number, the method fetches the list of accounts and returns the signer for the account at that index.
  2. **Account Address**: If the `address` is a string, it checks the list of accounts for the corresponding address and returns the signer for that address.

- **Account Resolution**:
  - The function makes a call to the JSON-RPC API method `eth_accounts` to retrieve the available accounts.
  - The `resolveProperties` utility is used to ensure that both the network and accounts are resolved before the account matching begins.

- **Error Handling**:
  - Throws an error if the specified account index is out of range.
  - Throws an error if the provided address is invalid or not found in the list of accounts.

## Example Usage

```typescript
import { JsonRpcApiProvider } from "./JsonRpcApiProvider";
import { OnboardInfo } from "../types";

// Create an instance of the provider for a specific network
const provider = new JsonRpcApiProvider("https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID");

// Example: Fetch the signer for the first account
const signer = await provider.getSigner(0);

// Example: Fetch the signer for a specific address with onboarding info
const userOnboardInfo: OnboardInfo = {
    aesKey: "user-aes-key",
    rsaKey: { publicKey: "rsa-public-key", privateKey: "rsa-private-key" },
    txHash: "transaction-hash"
};

const signerWithOnboarding = await provider.getSigner("0xYourEthereumAddress", userOnboardInfo);
```

# `JsonRpcSigner` Class

The `JsonRpcSigner` class extends the base `JsonRpcSigner` from `ethers.js` and adds additional functionality for onboarding users and managing encryption using AES keys within the Coti Network. It includes methods for securely encrypting and decrypting data, generating/recovering AES keys, and handling onboarding procedures.

## **Constructor**

```typescript
constructor(provider: JsonRpcApiProvider, address: string, userOnboardInfo?: OnboardInfo)
```

- **Parameters**:
  - `provider`: An instance of `JsonRpcApiProvider` for interacting with the blockchain.
  - `address`: A string representing the Ethereum address for this signer.
  - `userOnboardInfo?`: Optional `OnboardInfo` object containing user-specific data such as AES keys, RSA keys, and transaction hashes.

- **Description**: Initializes a new instance of the `JsonRpcSigner` class, optionally including user-specific onboarding information. It extends the functionality of the base `JsonRpcSigner` from `ethers` by incorporating encryption-related operations and user onboarding data.

## **Private Fields**

- **`_autoOnboard: boolean`**:
  - Determines whether the signer should automatically initiate onboarding if required.
  - Default value is `true`.

- **`_userOnboardInfo?: OnboardInfo`**:
  - Stores the user’s onboarding information, which may include the AES key, RSA key pair, and transaction hash.

## **Private Methods**

### **`#buildInputText(plaintext: bigint, userKey: string, contractAddress: string, functionSelector: string): Promise<itUint>`**

- **Parameters**:
  - `plaintext`: The plaintext value to encrypt, as a `bigint`.
  - `userKey`: The AES key for encrypting the plaintext.
  - `contractAddress`: The contract address associated with the transaction.
  - `functionSelector`: A string identifying the function to be called on the contract.

- **Returns**: A `Promise<itUint>` containing the encrypted data.

- **Description**: Encrypts the given plaintext using the user's AES key, ensuring the data size is within the 64-bit limit. It uses utility functions to encode the plaintext and the key, then encrypts the data. It prepares the encrypted value for transmission by packing it into a cryptographically signed message.

## **Public Methods**

### **`encryptValue(plaintextValue: bigint | number | string, contractAddress: string, functionSelector: string): Promise<itUint | itString>`**

- **Parameters**:
  - `plaintextValue`: The value to encrypt, which can be of type `bigint`, `number`, or `string`.
  - `contractAddress`: The smart contract address to which the encryption is related.
  - `functionSelector`: The function identifier for the contract interaction.

- **Returns**: A `Promise<itUint | itString>`, depending on the type of the plaintext value.

- **Description**: Encrypts the provided plaintext using the user’s AES key. If the AES key is not available, it attempts to generate or recover it via onboarding. The function handles both integer and string values and returns the encrypted result accordingly.

### **`decryptValue(ciphertext: ctUint | ctString): Promise<bigint | string>`**

- **Parameters**:
  - `ciphertext`: The encrypted value, which can either be of type `ctUint` (for integers) or `ctString` (for strings).

- **Returns**: A `Promise<bigint | string>`, depending on the ciphertext type.

- **Description**: Decrypts the provided ciphertext using the AES key stored in the user’s onboarding information. If the AES key is missing, it attempts to onboard the user or recover the key. The method supports decryption for both integers and strings.

### **`generateOrRecoverAes(onboardContractAddress: string = ONBOARD_CONTRACT_ADDRESS): Promise<void>`**

- **Parameters**:
  - `onboardContractAddress`: The contract address used for onboarding purposes. Defaults to `ONBOARD_CONTRACT_ADDRESS`.

- **Returns**: A `Promise<void>`.

- **Description**: This function attempts to generate or recover the user's AES key. If the AES key already exists in the onboarding information, it returns immediately. If the user’s RSA key and transaction hash are available, the AES key is recovered from the blockchain using the `recoverAesFromTx` function. If no onboarding info exists, it checks the user's account balance and initiates the onboarding process if the balance is sufficient.

- **Error Handling**:
  - Throws an error if the user's account balance is `0`, preventing onboarding.

## **Auto Onboarding Control**

- **Automatic onboarding**: This class supports automatic onboarding of users if their AES key is not available. The `_autoOnboard` flag controls whether the process is initiated automatically when needed.

## Example Usage

```typescript
import { JsonRpcProvider } from "ethers";
import { JsonRpcSigner } from "./JsonRpcSigner";
import { CotiNetwork, OnboardInfo } from "../types";

// Create a provider
const provider = new JsonRpcProvider(CotiNetwork.Devnet);

// Create a signer with user onboard info
const userOnboardInfo: OnboardInfo = {
    aesKey: "user-aes-key",
    rsaKey: { publicKey: "rsa-public-key", privateKey: "rsa-private-key" },
    txHash: "transaction-hash"
};

const signer = new JsonRpcSigner(provider, "0xUserAddress", userOnboardInfo);

// Encrypt a value
const encryptedValue = await signer.encryptValue(BigInt(1000), "0xContractAddress", "0xFunctionSelector");

// Decrypt a value
const decryptedValue = await signer.decryptValue(encryptedValue);
```

# `Account Utilities` Module

This module provides utility functions for managing and interacting with accounts in an Ethereum-compatible blockchain using `ethers.js`. It includes functions for retrieving account details, checking balances, validating addresses, handling nonces, and transferring native tokens between accounts.

## Imports

- **`ethers`**:
  - `formatEther`: Converts a value in wei (the smallest unit in Ethereum) to ether.
  - `getAddress`: Normalizes and checksums an Ethereum address.
  - `isAddress`: Checks if a given string is a valid Ethereum address.
  - `Provider`: An abstraction of a connection to the Ethereum network.
  - `TransactionRequest`: An object representing a transaction request to be sent to the blockchain.
  - `Wallet`: An object representing an Ethereum wallet that holds keys for signing transactions.

- **Local Imports**:
  - `isProviderConnected`: Checks if a provider is connected to the network.
  - `validateGasEstimation`: Validates the gas estimation of a transaction.

## Functions

### 1. **`printAccountDetails(provider: Provider, address: string): Promise<void>`**

- **Parameters**:
  - `provider`: An instance of `Provider` to interact with the blockchain.
  - `address`: A string representing the account’s address.

- **Returns**: A `Promise<void>` that resolves once the account details are printed.

- **Description**: This function prints the details of a given account to the console, including:
  - The account's address.
  - The account's balance in both wei and ether.
  - The account's transaction nonce.

- **Error Handling**:
  - Throws an error if the provider is not connected or the address is invalid.

### 2. **`getAccountBalance(address: string, provider: Provider): Promise<BigInt>`**

- **Parameters**:
  - `address`: A string representing the account’s address.
  - `provider`: An instance of `Provider` to interact with the blockchain.

- **Returns**: A `Promise<BigInt>` that resolves to the balance of the account in wei.

- **Description**: This function retrieves the balance of the specified account in wei from the blockchain.

- **Error Handling**:
  - Throws an error if the provider is not connected or the address is invalid.

### 3. **`validateAddress(address: string): { valid: boolean, safe: string }`**

- **Parameters**:
  - `address`: A string representing the account’s address.

- **Returns**: An object containing:
  - `valid`: A boolean indicating if the address is valid.
  - `safe`: A checksummed version of the address (a safer, standardized format).

- **Description**: This function validates the format of a given Ethereum address and returns both a boolean (`valid`) and a safe, checksummed version (`safe`) of the address.

### 4. **`getNonce(provider: Provider, address: string): Promise<number>`**

- **Parameters**:
  - `provider`: An instance of `Provider` to interact with the blockchain.
  - `address`: A string representing the account’s address.

- **Returns**: A `Promise<number>` that resolves to the account's nonce, which represents the number of transactions sent from the address.

- **Description**: This function retrieves the current transaction nonce for the given account, which is essential for ensuring the correct order of transactions on the blockchain.

- **Error Handling**:
  - Throws an error if the provider is not connected or the address is invalid.

### 5. **`addressValid(address: string): boolean`**

- **Parameters**:
  - `address`: A string representing the account’s address.

- **Returns**: A boolean indicating whether the address is valid.

- **Description**: This function validates an Ethereum address by returning a boolean (`true` if valid, `false` otherwise).

### 6. **`getNativeBalance(provider: Provider, address: string): Promise<string>`**

- **Parameters**:
  - `provider`: An instance of `Provider` to interact with the blockchain.
  - `address`: A string representing the account’s address.

- **Returns**: A `Promise<string>` that resolves to the account balance in ether (as a formatted string).

- **Description**: This function retrieves the account’s balance in ether (instead of wei) by formatting the balance using `formatEther`.

- **Error Handling**:
  - Throws an error if the provider is not connected or the address is invalid.

### 7. **`getEoa(accountPrivateKey: string): Promise<string>`**

- **Parameters**:
  - `accountPrivateKey`: A string representing the private key of the account.

- **Returns**: A `Promise<string>` that resolves to the Ethereum address generated from the private key.

- **Description**: This function generates an Ethereum address (EOA) from the given private key and returns it.

- **Error Handling**:
  - Throws an error if the generated address is invalid.

### 8. **`transferNative(provider: Provider, wallet: Wallet, recipientAddress: string, amountToTransferInWei: BigInt, nativeGasUnit: number): Promise<void>`**

- **Parameters**:
  - `provider`: An instance of `Provider` to interact with the blockchain.
  - `wallet`: An instance of `Wallet` that represents the sender's account.
  - `recipientAddress`: A string representing the recipient's Ethereum address.
  - `amountToTransferInWei`: The amount of native tokens to transfer, in wei.
  - `nativeGasUnit`: The gas limit for the transaction.

- **Returns**: A `Promise<void>`.

- **Description**: This function transfers native tokens (e.g., ETH) from the sender's wallet to a recipient. It constructs a transaction, validates the gas estimation, and sends the transaction using the sender’s wallet.

- **Error Handling**:
  - Throws an error if the transaction fails.
  - Logs the transaction hash on success or error details if it fails.

- **Transaction Details**:
  - The transaction includes details like `to` (recipient address), `from` (sender address), `value` (amount in wei), `nonce`, `gasLimit`, and `gasPrice`.

## Error Handling

All functions handle errors related to:
- **Invalid Provider**: Several functions check if the `Provider` is connected using `isProviderConnected`. If the provider is disconnected or invalid, an error is thrown.
- **Invalid Address**: Functions that accept an address validate it using `isAddress` and throw an error if the address is invalid.
- **Transaction Failures**: The `transferNative` function catches errors during transaction execution and logs the failure, ensuring that the error details are visible.

## Example Usage

```typescript
import { getDefaultProvider, Wallet } from "ethers";
import { printAccountDetails, transferNative, getEoa, getNativeBalance } from "./accountUtils";
import { CotiNetwork } from "../types";

// Example: Printing account details
const provider = getDefaultProvider(CotiNetwork.Devnet);
const address = "0xYourEthereumAddress";

await printAccountDetails(provider, address);

// Example: Transferring native tokens
const senderPrivateKey = "0xYourPrivateKey";
const senderWallet = new Wallet(senderPrivateKey, provider);
const recipientAddress = "0xRecipientAddress";
const amountToTransferInWei = BigInt("1000000000000000000"); // 1 ether in wei
const gasLimit = 21000;

await transferNative(provider, senderWallet, recipientAddress, amountToTransferInWei, gasLimit);
```

# `Network Utilities` module

This module provides utility functions for interacting with the COTI network through `ethers` providers. It includes functions to fetch the default provider, check if a provider is connected, print network details, and retrieve the latest block number.

## Functions

### 1. **`getDefaultProvider(cotiNetwork: CotiNetwork): JsonRpcProvider`**

- **Parameters**:
  - `cotiNetwork`: An instance of `CotiNetwork` that specifies the network (Devnet, Testnet, Mainnet, etc.) the provider should connect to.
  
- **Returns**: An instance of `JsonRpcProvider`.

- **Description**: This function returns a `JsonRpcProvider` configured to connect to the specified `CotiNetwork`. It uses the `cotiNetwork` URL to set up the provider for the specified environment.

### 2. **`async printNetworkDetails(provider: Provider): Promise<void>`**

- **Parameters**:
  - `provider`: An instance of `Provider` that is connected to the Coti network.
  
- **Returns**: A `Promise<void>`, which resolves after network details are printed to the console.

- **Description**: This function prints the details of the network to which the provider is connected, including:
  - The provider's connection URL (if using a `JsonRpcProvider`).
  - The `chainId` of the network.
  - The number of the latest block on the blockchain.

- **Error Handling**:
  - Throws an error if the provider is not connected.

- **Usage**:
  This function logs the following details:
  - Provider URL (`url`)
  - Chain ID (`chainId`)
  - Latest block number
  
  Example:
  ```typescript
  const provider = getDefaultProvider(CotiNetwork.Mainnet);
  await printNetworkDetails(provider);
  ```

### 3. **`async getLatestBlock(provider: Provider): Promise<number>`**

- **Parameters**:
  - `provider`: An instance of `Provider` that is connected to the Coti network.
  
- **Returns**: A `Promise<number>`, which resolves to the block number of the latest block in the network.

- **Description**: This function retrieves the block number of the most recent block on the blockchain. It first checks if the provider is connected, then queries the provider for the latest block.

- **Error Handling**:
  - Throws an error if the provider is not connected or if the provider’s address is invalid.

### 4. **`async isProviderConnected(provider: Provider): Promise<boolean>`**

- **Parameters**:
  - `provider`: An instance of `Provider`.
  
- **Returns**: A `Promise<boolean>`, which resolves to `true` if the provider is connected to a network, or `false` if the connection is unsuccessful.

- **Description**: This function checks if a given provider is connected to a valid network by querying the network information. If the provider's network cannot be fetched, it returns `false`. This function also throws an error if the provider is undefined.

- **Error Handling**:
  - Throws an error if the `provider` object is undefined.

## Example Usage

```typescript
import { getDefaultProvider, printNetworkDetails, getLatestBlock, isProviderConnected } from './providerUtils';
import { CotiNetwork } from '../types';

// Get the default provider for Devnet
const provider = getDefaultProvider(CotiNetwork.Devnet);

// Check if the provider is connected
const isConnected = await isProviderConnected(provider);
if (isConnected) {
    // Print the network details
    await printNetworkDetails(provider);
    
    // Get and log the latest block number
    const latestBlock = await getLatestBlock(provider);
    console.log(`The latest block number is: ${latestBlock}`);
} else {
    console.log('Provider is not connected.');
}
```

# Class `Wallet`

The `Wallet` class extends the base `Wallet` from the `ethers` library, adding features specific to the COTI network. It handles user onboarding, key management, and encryption/decryption of values using AES and RSA keys. The class also supports the process of automatically onboarding users if needed.

## Constructor

```typescript
constructor(
    privateKey: string | SigningKey,
    provider?: Provider | null,
    userOnboardInfo?: OnboardInfo
)
```

- **Parameters**:
  - `privateKey`: A `string` or `SigningKey` used to initialize the wallet.
  - `provider?`: An optional `Provider` object or `null`. Defaults to `null` if not provided.
  - `userOnboardInfo?`: An optional `OnboardInfo` object that contains the user's onboarding data (e.g., AES key, RSA key).

- **Description**: Initializes a new `Wallet` instance with a given private key, provider, and optional user onboarding information. This class extends the `BaseWallet` from the `ethers` library, inheriting its functionality.


## Private Fields

- **`_autoOnboard: boolean`**:
  - Description: This flag determines whether automatic onboarding is enabled or disabled. By default, it is set to `true`.
  
- **`_userOnboardInfo?: OnboardInfo`**:
  - Description: Stores the user's onboarding information, which may include the AES key, RSA key, and transaction hash for secure operations on the Coti network.

## Methods

### 1. **`getAutoOnboard(): boolean`**

- **Returns**: `boolean`
- **Description**: Returns the current state of the `_autoOnboard` flag, which indicates whether automatic onboarding is enabled.

### 2. **`getUserOnboardInfo(): OnboardInfo | undefined`**

- **Returns**: `OnboardInfo | undefined`
- **Description**: Retrieves the user's onboarding information, or `undefined` if no onboarding info is present.

### 3. **`setUserOnboardInfo(onboardInfo?: Partial<OnboardInfo> | undefined | null)`**

- **Parameters**:
  - `onboardInfo`: An optional object of type `Partial<OnboardInfo>` to update or modify the existing onboarding information.
  
- **Description**: Updates the current user's onboarding info by merging the new `onboardInfo` values with the existing ones.

### 4. **`setAesKey(key: string)`**

- **Parameters**:
  - `key`: The AES encryption key to set in the user's onboarding information.

- **Description**: Assigns the AES key to the user’s onboarding information. If onboarding info doesn’t exist, it creates a new onboarding object with the provided key.

### 5. **`setOnboardTxHash(hash: string)`**

- **Parameters**:
  - `hash`: The transaction hash associated with the user's onboarding process.

- **Description**: Sets the transaction hash in the user’s onboarding info. If onboarding info is absent, it creates a new one with the hash.

### 6. **`setRsaKeyPair(rsa: RsaKeyPair)`**

- **Parameters**:
  - `rsa`: The RSA key pair for encryption/decryption.

- **Description**: Stores the provided RSA key pair in the user’s onboarding info. If the onboarding object is not present, it initializes a new one with the given RSA key.

### 7. **`async encryptValue(plaintextValue: bigint | number | string, contractAddress: string, functionSelector: string): Promise<itUint | itString>`**

- **Parameters**:
  - `plaintextValue`: The value to encrypt, which can be of type `bigint`, `number`, or `string`.
  - `contractAddress`: The address of the smart contract involved in the encryption.
  - `functionSelector`: A string that identifies the specific contract function to which this encryption pertains.
  
- **Returns**: A promise that resolves to either `itUint` or `itString`, depending on the type of the value.
  
- **Description**: Encrypts the provided `plaintextValue` using the user’s AES key. If the AES key is missing, it attempts to generate or recover it. It handles both `bigint` and `string` values.

### 8. **`async decryptValue(ciphertext: ctUint | ctString): Promise<string | bigint>`**

- **Parameters**:
  - `ciphertext`: The encrypted value, either a `ctUint` (for integers) or a `ctString` (for strings).
  
- **Returns**: A promise that resolves to either a `string` or `bigint`, depending on the ciphertext type.
  
- **Description**: Decrypts the given ciphertext using the user’s AES key. If the AES key is not available, it attempts to generate or recover it. Handles both integer and string decryption.

### 9. **`enableAutoOnboard()`**

- **Description**: Enables automatic onboarding by setting the `_autoOnboard` flag to `true`.

### 10. **`disableAutoOnboard()`**

- **Description**: Disables automatic onboarding by setting the `_autoOnboard` flag to `false`.

### 11. **`clearUserOnboardInfo()`**

- **Description**: Clears the stored user onboarding information by setting `_userOnboardInfo` to `undefined`.

### 12. **`async generateOrRecoverAes(onboardContractAddress: string = DEVNET_ONBOARD_CONTRACT_ADDRESS)`**

- **Parameters**:
  - `onboardContractAddress`: The contract address for onboarding purposes. Defaults to `DEVNET_ONBOARD_CONTRACT_ADDRESS`.
  
- **Description**: Attempts to generate or recover the user’s AES key:
  - If the AES key exists in the user’s onboarding info, it returns immediately.
  - If the user’s RSA key and transaction hash are available, the AES key is recovered from the blockchain transaction using `recoverAesFromTx`.
  - If neither AES nor RSA keys are available, it attempts to onboard the user by checking their account balance and invoking the onboarding process.
  
- **Throws**: Throws an error if the account balance is 0, preventing the user from being onboarded.