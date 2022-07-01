import { ApiPromise, WsProvider } from "@polkadot/api";

const westend = 'wss://westend-rpc.polkadot.io';
const kusama = 'wss://kusama-rpc.polkadot.io';
const mainnet = 'wss://rpc.polkadot.io';

const getRpc = async (uri) => {
    const provider = new WsProvider(uri);
    return await ApiPromise.create({ provider });
}

/**
 * 
 * @param {ApiPromise} api 
 * @param {string} block 
 * @param {number} index 
 */
const getUsedFee = async (api, blockHash, txHash)=> {
    const signedBlock = await api.rpc.chain.getBlock(blockHash);
    const apiAt = await api.at(signedBlock.block.hash);
    const allRecords = await apiAt.query.system.events();

    Promise.all(
        signedBlock.block.extrinsics
            .filter((extrinsic) => extrinsic.hash.eq(txHash))
            .map((extrinsic) => api.rpc.payment.queryFeeDetails(extrinsic.toHex(), signedBlock.block.hash))
    ).then((details) => {
        details.forEach(detail => {
            const fees = detail.toJSON().inclusionFee;
            const totalFee = Object.values(fees).reduce((fee, sum) => sum + fee, 0);
            console.log(totalFee);
        })
    }).catch((err) => console.log(err))
    .finally(async () => await api.disconnect())
}

getRpc(westend)
    .then((api) => getUsedFee(api, "0x64b385933932162e9570413877743da123049a7f34d309cf62f40afbee2cb83a", "0xed8df736c7319724ed6b8af999d8ffb24db201c992e6a25490845c11b80a0341"))
    .catch((err) => console.error(err));