import { ApiPromise, WsProvider } from '@polkadot/api';
import { Keyring } from '@polkadot/keyring';
import HdKey from 'hdkey';
import { u8aToHex, hexToU8a } from '@polkadot/util';
import wtx from '@substrate/txwrapper-polkadot'
import { signatureVerify,encodeAddress, blake2AsU8a } from '@polkadot/util-crypto';

// const xprv = 'xprvA26roNwRgtH6iuD5c2DoFewGAR9yTETjAGuTgQRPyXUVBvVkJoaVwiF9xmuyvWk1NBukLgVK4i76NHXj1tDHMuGqUnedAfBA19wo1iqsUeD'
const xpub = 'xpub6BxS8hHq2pPeFcdC5xg8pzdKqmPcK4xSspn2992gpHj4WvyLd3Y3URdUpXqECnkKWFu7cvJXUQiGRhNwAFno1NXSyU5FVtQmGPpDwsijfdH';
const TYPE_ADDRESS = {
    ecdsa: p => p.length > 32 ? blake2AsU8a(p) : p,
    ed25519: p => p,
    ethereum: p => p.length === 20 ? p : keccakAsU8a(secp256k1Expand(p)),
    sr25519: p => p
  };

// HotWalletの役割:
// BIP32に従ってxpubからパスを指定してアドレス生成
// 未署名Txの作成
// 署名の検証
class Wallet {
    hdkey;
    ss58Format;
    sigType;

    constructor (xpub, ss58Format) {
        // Construct
        this.ss58Format = ss58Format;
        this.hdkey = HdKey.fromExtendedKey(xpub);
        this.sigType = 'ecdsa'
    }

    generateAddress(index) {
        const derivedKey = hdkey.derive(`m/44/354/0/0/${index}`);

        console.log(derivedKey.publicKey.length);

        const keyring = new Keyring({ type: this.sigType, ss58Format: this.ss58Format});
        const pub_modified = TYPE_ADDRESS[sigType](derivedKey.publicKey)
        const address = keyring.encodeAddress(pub_modified, ss58Format);

        console.log(
            `address: ${address}\n` + 
            `xpub   : ${u8aToHex(keyPair.publicKey)}\n`
        )

        return address
    }

    verify(message, signature) {
        return signatureVerify(message, signature, this.address);
    }

    async getRpc() {
        const wsProvider = new WsProvider('wss://westend-rpc.polkadot.io');
        return await ApiPromise.create({ provider: wsProvider })
    }

    async createUnsignedTx(address, dest, amount, baseArgExt) {
        const api = await this.getRpc()

        const { block } = await api.rpc.chain.getBlock();
        const blockHash = await api.rpc.chain.getBlockHash();
        const genesisHash = await api.rpc.chain.getBlockHash(0);
        const { specVersion, transactionVersion } = await api.rpc.state.getRuntimeVersion();
        const metadataRpc = await api.rpc.state.getMetadata();

        const nonce = await api.rpc.system.accountNextIndex(address);

        const registry = api.registry;
        registry.setMetadata(metadataRpc);

        const utx = wtx.methods.balances.transferKeepAlive({dest: dest, value: amount}, {
            address: address,
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
            `\nDecoded Unsigned Transaction\n` + 
                `  To: ${(decodedUnsigned.method.args.dest)?.id}\n` +
                `  Amount: ${decodedUnsigned.method.args.value}\n` +
                decodedUnsigned,
        );

        return utx;
    }

    async broadcast(tx) {
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

    // signTx(utx) {
    //     const sigPayload = wtx.construct.signingPayload(utx, { metadataRpc, registry });
    //     const payloadInfo = wtx.decode(sigPayload, {
    //         metadataRpc,
    //         registry,
    //     });
    //     console.log(
    //         `\nDecoded Transaction Payload\n` +
    //             `  To: ${(payloadInfo.method.args.dest)?.id}\n` +
    //             `  Amount: ${payloadInfo.method.args.value}\n` +
    //             payloadInfo
    //     );
    
    //     const extrinsicPayload = registry.createType('ExtrinsicPayload', sigPayload, {
	// 		version: utx.version,
	// 	});
    //     const { signature } = extrinsicPayload.sign(this.keyringPair);

    //     const tx = wtx.construct.signedTx(utx, signature, {
    //         metadataRpc,
    //         registry
    //     });
    //     return tx;
    // }
}

const wallet = new Wallet(xpub, 42);
wallet.createUnsignedTx(wallet.generateAddress(1), wallet.generateAddress(2), 1000000);
