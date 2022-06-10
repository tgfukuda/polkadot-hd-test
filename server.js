import { ApiPromise, WsProvider } from '@polkadot/api';
import { Keyring } from '@polkadot/keyring';
import HdKey from 'hdkey';
import wtx from '@substrate/txwrapper-polkadot'
import { signatureVerify, blake2AsU8a } from '@polkadot/util-crypto';
import { u8aToHex } from '@polkadot/util';

const xprv = 'xprv9xzjfWD4jQawLFRuvj7F1mLgAmFXmVeFiAjKCasAkST495HKf6Ug28aRasRxyrnDQSJUj3Wj7kxvBirtDmAyR8cDfRQgRTWWYmyvG2NHwmF'
const xpub = 'xpub6BxS8hHq2pPeFcdC5xg8pzdKqmPcK4xSspn2992gpHj4WvyLd3Y3URdUpXqECnkKWFu7cvJXUQiGRhNwAFno1NXSyU5FVtQmGPpDwsijfdH';
const TYPE_ADDRESS = {
    ecdsa: p => p.length > 32 ? blake2AsU8a(p) : p,
    ed25519: p => p,
    ethereum: p => p.length === 20 ? p : keccakAsU8a(secp256k1Expand(p)),
    sr25519: p => p
  };

// HotWallet capabilities:
// generate address with given HDPath according to BIP32
// generate unsigned transaction
// verify signed transaction
// broadcast signed transaction
class ServerWallet {
    hdkey;
    ss58Format;
    sigType;

    constructor (xpub, ss58Format) {
        this.ss58Format = ss58Format;
        this.hdkey = HdKey.fromExtendedKey(xpub);
        this.sigType = 'ecdsa'
    }

    generateAddress(index) {
        const derivedKey = this.hdkey.derive(`m/44/354/0/0/${index}`);
        const keyring = new Keyring({ type: this.sigType, ss58Format: this.ss58Format});
        const pub_modified = TYPE_ADDRESS[this.sigType](derivedKey.publicKey)
        const address = keyring.encodeAddress(pub_modified, this.ss58Format);
        return address
    }

    verifySig(message, signature, index) {
        const address = this.generateAddress(index);
        return signatureVerify(message, signature, address);
    }

    async getRpc() {
        const wsProvider = new WsProvider('wss://westend-rpc.polkadot.io');
        return await ApiPromise.create({ provider: wsProvider })
    }

    async createUnsignedTx(senderAddress, destAddress, amount, baseArgExt) {
        const api = await this.getRpc()

        const { block } = await api.rpc.chain.getBlock();
        const blockHash = await api.rpc.chain.getBlockHash();
        const genesisHash = await api.rpc.chain.getBlockHash(0);
        const { specVersion, transactionVersion } = await api.rpc.state.getRuntimeVersion();
        const metadataRpc = await api.rpc.state.getMetadata();

        const nonce = await api.rpc.system.accountNextIndex(senderAddress);

        const registry = api.registry;
        registry.setMetadata(metadataRpc);

        const unsignedTx = wtx.methods.balances.transferKeepAlive({dest: destAddress, value: amount}, {
            address: senderAddress,
            blockHash,
            blockNumber: registry.createType('BlockNumber', block.header.number).toNumber(),
            genesisHash,
            metadataRpc,
            nonce,
            specVersion,
            transactionVersion,
            tip: 0,
            ...baseArgExt,
        }, {
            metadataRpc,
            registry,
        });

        const decodedUnsigned = wtx.decode(unsignedTx, {
            metadataRpc,
            registry,
        });

        console.log(
            `\nDecoded Unsigned Transaction\n` + 
                `  To: ${(decodedUnsigned.method.args.dest)?.id}\n` +
                `  Amount: ${decodedUnsigned.method.args.value}\n`
        );
        const signingPayload = wtx.construct.signingPayload(unsignedTx, { metadataRpc, registry });
        const extrinsicPayload = registry.createType('ExtrinsicPayload', signingPayload, {
			version: unsignedTx.version,
		});
        const extrinsicPayloadU8a = extrinsicPayload.toU8a({ method: true })
        const actualPayload = extrinsicPayloadU8a.length > 256
            ? registry.hash(extrinsicPayloadU8a)
            : extrinsicPayloadU8a;
        api.disconnect();

        return { payload: u8aToHex(actualPayload), unsignedTx };
    }


    async constructTx(unsignedTx, signature) {
        const api = await this.getRpc()
        const registry = api.registry;
        const metadataRpc = await api.rpc.state.getMetadata();
        registry.setMetadata(metadataRpc);
        const tx = wtx.construct.signedTx(unsignedTx, signature, {
            metadataRpc,
            registry
        });
        this.broadcast(tx);
        return tx
    }

    async broadcast(signedTx) {
        const api = await this.getRpc()
        const registry = api.registry;
        const metadataRpc = await api.rpc.state.getMetadata();

        // Decode a signed payload.
        const txInfo = wtx.decode(signedTx, {
            metadataRpc,
            registry,
        });
        console.log(
            `\nDecoded Transaction\n`+
                `  To: ${(txInfo.method.args.dest)?.id}\n` +
                `  Amount: ${txInfo.method.args.value}\n`
        );

        const actualTx = await api.rpc.author.submitExtrinsic(api.createType('Extrinsic', signedTx));
        console.log("\nactual tx hash:", actualTx.toHex());

        await api.disconnect();
        return actualTx.toHex()
    }
}

const wallet = new ServerWallet(xprv, 42);

for (let i = 0; i <= 10; i++) {
    console.log(`index: ${i}: ${wallet.generateAddress(i)}`);
}
const unsigned = await wallet.createUnsignedTx(wallet.generateAddress(0),"5ERabPpv3puKx6fVDYTgUcHz8C8xXwNPGE7sjfdeFKBV6uJb", 1000000);
console.log(unsigned.payload)
const result = await wallet.constructTx(unsigned.unsignedTx, "0x025c2effb16ed7f9f6a700e8b9b72bf80c2a0f34151a7f5895957a48a25407b1f23364b7fa1590d8f0b91b29bfc0778c536751f72a1fa9f4fc7fc89f973969b81401");

console.log(result);