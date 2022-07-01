import { ApiPromise, WsProvider } from "@polkadot/api";

class Subscriber {
    uri;

    constructor(uri) {
        this.uri = uri;
    }

    async getRpc() {
        const wsProvider = new WsProvider(this.uri);
        return await ApiPromise.create({ provider: wsProvider })
    }

    async start() {
        const api = await this.getRpc();

        const isRewarded = api.events.staking.Rewarded.is;

        api.query.system.events((events) => {
            console.log(`\nReceived ${events.length} events:`);

            // Loop through the Vec<EventRecord>
            events.forEach((record) => {
                // Extract the phase, event and the event types
                const {
                    event,
                    phase 
                } = record;
                const types = event.typeDef;

                if (isRewarded(event)) {
                    const receipt = event.data.toJSON();
                    const address = receipt[0];
                    const balance = receipt[1];
                    console.log("staking");
                    console.log("address:", address, "\nbalance:", balance);
                }
            });
        });
    }
}

const westend = 'wss://westend-rpc.polkadot.io';
const kusama = 'wss://kusama-rpc.polkadot.io';
const mainnet = 'wss://rpc.polkadot.io';

const subs = new Subscriber(kusama);
subs.start();