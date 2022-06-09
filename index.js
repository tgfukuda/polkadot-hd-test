import { ApiPromise, WsProvider } from '@polkadot/api';
import { Keyring } from '@polkadot/keyring';
import HdKey from 'hdkey';
import { u8aToHex, hexToU8a } from '@polkadot/util';
import wtx from '@substrate/txwrapper-polkadot'
import { signatureVerify,encodeAddress, blake2AsU8a } from '@polkadot/util-crypto';

const xprv = 'xprv9xzjfWD4jQawLFRuvj7F1mLgAmFXmVeFiAjKCasAkST495HKf6Ug28aRasRxyrnDQSJUj3Wj7kxvBirtDmAyR8cDfRQgRTWWYmyvG2NHwmF'

const TYPE_ADDRESS = {
    ecdsa: p => p.length > 32 ? blake2AsU8a(p) : p,
    ed25519: p => p,
    ethereum: p => p.length === 20 ? p : keccakAsU8a(secp256k1Expand(p)),
    sr25519: p => p
  };

class Wallet {
    keyringPair;
    address;
    keyPair;

    constructor (xprv, ss58Format) {
        // Construct

        const hdkey = HdKey.fromExtendedKey(xprv);
        const derivedKey = hdkey.derive("m/44/354/0/0/0");

        console.log(derivedKey.publicKey.length, derivedKey.privateKey.length);

        const sigType = 'ecdsa'

        const keyring = new Keyring({ type: sigType, ss58Format: ss58Format});
        const pub_modified = TYPE_ADDRESS[sigType](derivedKey.publicKey)
        this.address = keyring.encodeAddress(pub_modified, ss58Format);           

        const keyPair = { publicKey: pub_modified, secretKey: derivedKey.privateKey };
        this.keyPair = keyPair;
        this.keyringPair = keyring.createFromPair(keyPair, {}, sigType);

        if (true) {
            console.log(
                `address: ${this.address}\n` + 
                `xpriv  : ${u8aToHex(this.keyPair.secretKey)}\n` +
                `xpub   : ${u8aToHex(this.keyPair.publicKey)}\n`
            )
        }
    }

    get client() {
        return this.client;
    }

    get address() {
        return this.address;
    }

    get keyringPair() {
        return this.keyringPair;
    }

    signAndVerify(message) {
        const sig = this.keyringPair.sign(message);
        return signatureVerify(message, sig, this.address);
    }

    async getRpc() {
        const wsProvider = new WsProvider('wss://westend-rpc.polkadot.io');
        return await ApiPromise.create({ provider: wsProvider })
    }

    async createTx(transferArg, baseArgExt) {
        const api = await this.getRpc()

        const { block } = await api.rpc.chain.getBlock();
        const blockHash = await api.rpc.chain.getBlockHash();
        const genesisHash = await api.rpc.chain.getBlockHash(0);
        const { specVersion, transactionVersion, specName } = await api.rpc.state.getRuntimeVersion();
        const metadataRpc = await api.rpc.state.getMetadata();

        const nonce = await api.rpc.system.accountNextIndex(this.address);

        const registry = api.registry;
        registry.setMetadata(metadataRpc);

        const utx = wtx.methods.balances.transferKeepAlive(transferArg, {
            address: this.address,
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
        const decodedUnsigned = wtx.decode(utx, {
            metadataRpc,
            registry,
        });
        console.log(
            `\nDecoded Unsined Transaction\n` + 
                `  To: ${(decodedUnsigned.method.args.dest)?.id}\n` +
                `  Amount: ${decodedUnsigned.method.args.value}\n` +
                decodedUnsigned,
        );

        const sigPayload = wtx.construct.signingPayload(utx, { metadataRpc, registry });
        const payloadInfo = wtx.decode(sigPayload, {
            metadataRpc,
            registry,
        });
        console.log(
            `\nDecoded Transaction Payload\n` +
                `  To: ${(payloadInfo.method.args.dest)?.id}\n` +
                `  Amount: ${payloadInfo.method.args.value}\n` +
                payloadInfo
        );
    
        const extrinsicPayload = registry.createType('ExtrinsicPayload', sigPayload, {
			version: utx.version,
		});
        const { signature } = extrinsicPayload.sign(this.keyringPair);

        const tx = wtx.construct.signedTx(utx, signature, {
            metadataRpc,
            registry
        });
        console.log(`\nTransaction to Submit: ${tx}`);
        console.log("expected tx hash:", wtx.construct.txHash(tx));

        // Decode a signed payload.
        const txInfo = wtx.decode(tx, {
            metadataRpc,
            registry,
        });
        console.log(
            `\nDecoded Transaction\n`+
                `  To: ${(txInfo.method.args.dest)?.id}\n` +
                `  Amount: ${txInfo.method.args.value}\n` +
                txInfo
        );

        const actualTx = await api.rpc.author.submitExtrinsic(api.createType('Extrinsic', tx));
        console.log("\nactual tx hash:", actualTx.toHex());

        await api.disconnect();
    }
}

const wallet = new Wallet(xprv, 42);
wallet.createTx({
    value: 1000000,
    dest: "5ERabPpv3puKx6fVDYTgUcHz8C8xXwNPGE7sjfdeFKBV6uJb"
});
