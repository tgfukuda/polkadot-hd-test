import { ApiPromise, WsProvider } from '@polkadot/api';
import { Keyring } from '@polkadot/keyring';
import HdKey from 'hdkey';
import wtx from '@substrate/txwrapper-polkadot'
import { signatureVerify, blake2AsU8a } from '@polkadot/util-crypto';
import { u8aToHex } from '@polkadot/util';

import { ColdWallet } from './coldWallet.js';
const xprv = 'xprvA1pXchSD4UUY78FYVa7RsnWzz437a4QeX1i2e22AcgGmWJ9gEyh9XkSBtWjHXF63UTuAg6MgBqMwT8fGnGAH2StPwwzwCBBRKtPUnqbf7GP'
const xpub = 'xpub6Eot2Cy6tr2qKcL1bbeSEvTjY5sbyX8VtEddSQRnB1okP6UpnX1Q5YkfjndnhmoGX9fVMxGxzi9HiKCSDKhbMmMTMFCRZ7PuoUjXLWuqfYR';
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
        return tx
    }

    async broadcast(signedTx) {
        const api = await this.getRpc()
        const registry = api.registry;
        const metadataRpc = await api.rpc.state.getMetadata();
        registry.setMetadata(metadataRpc);
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
        await api.disconnect();
        return actualTx.toHex()
    }
}

// Instantiate wallet on server side with xPub.
const wallet = new ServerWallet(xpub, 42);


// Check that it can generate addresses just with xPub
for (let i = 0; i <= 10; i++) {
    console.log(`index: ${i}: ${wallet.generateAddress(i)}`);
}

// Send some funds
const index = 0

// store the result into db
const unsigned = await wallet.createUnsignedTx(wallet.generateAddress(index),"5ERabPpv3puKx6fVDYTgUcHz8C8xXwNPGE7sjfdeFKBV6uJb", 1000000);
console.log(unsigned.payload)

// Sign the payload with cold wallet
// In production, this is done on a seperate machine
const coldWallet = new ColdWallet(xprv, 42)
const signature = coldWallet.signTx(unsigned.payload, index)

// Return the signature to the server
// The server will concatinate the transaction with the signature
const signedTx = await wallet.constructTx(unsigned.unsignedTx, signature);

// Broadcast the tx
const result = await wallet.broadcast(signedTx);

console.log(result);