import { Provider, toNumber, TransactionRequest } from "ethers";

export async function validateGasEstimation(provider: Provider, tx: TransactionRequest) {
    const {valid, gasEstimation} = await isGasEstimationValid(provider, tx);
    if (!valid)
        throw new Error(`Not enough gas for tx. Provided: ${tx.gasLimit}, needed: ${gasEstimation}`);
}

export async function isGasEstimationValid(provider: Provider, tx: TransactionRequest) {
    const estimatedGas = await provider.estimateGas(tx)
    const gasLimit = tx.gasLimit ? toNumber(tx.gasLimit) : 0;

    if (!estimatedGas || estimatedGas > gasLimit) {
        throw new Error(`Not enough gas for tx. Provided: ${gasLimit}, needed: ${estimatedGas.toString()}`);
    }
    return {valid: true, gasEstimation: estimatedGas}
}