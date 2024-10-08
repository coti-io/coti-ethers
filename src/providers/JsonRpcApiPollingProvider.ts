import {JsonRpcApiProviderOptions, Networkish, Subscriber, Subscription} from "ethers"
import {JsonRpcApiProvider} from "./JsonRpcApiProvider"

const defaultOptions = {
    polling: false,
    staticNetwork: null,

    batchStallTime: 10,      // 10ms
    batchMaxSize: (1 << 20), // 1Mb
    batchMaxCount: 100,      // 100 requests

    cacheTimeout: 250,
    pollingInterval: 4000
}

interface Pollable {
    pollingInterval: number;
}

function isPollable(value: any): value is Pollable {
    return (value && typeof(value.pollingInterval) === "number");
}

export abstract class JsonRpcApiPollingProvider extends JsonRpcApiProvider {
    #pollingInterval: number;
    constructor(network?: Networkish, options?: JsonRpcApiProviderOptions) {
        super(network, options);

        let pollingInterval = this._getOption("pollingInterval");
        if (pollingInterval == null) { pollingInterval = defaultOptions.pollingInterval; }

        this.#pollingInterval = pollingInterval;
    }

    _getSubscriber(sub: Subscription): Subscriber {
        const subscriber = super._getSubscriber(sub);
        if (isPollable(subscriber)) {
            subscriber.pollingInterval = this.#pollingInterval;
        }
        return subscriber;
    }

    /**
     *  The polling interval (default: 4000 ms)
     */
    get pollingInterval(): number { return this.#pollingInterval; }
    set pollingInterval(value: number) {
        if (!Number.isInteger(value) || value < 0) { throw new Error("invalid interval"); }
        this.#pollingInterval = value;
        this._forEachSubscriber((sub) => {
            if (isPollable(sub)) {
                sub.pollingInterval = this.#pollingInterval;
            }
        });
    }
}