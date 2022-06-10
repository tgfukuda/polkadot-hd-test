import { Keyring } from '@polkadot/keyring';
import HdKey from 'hdkey';
import { signatureVerify, blake2AsU8a } from '@polkadot/util-crypto';
import { u8aToHex } from '@polkadot/util';

const xprv = 'xprv9xzjfWD4jQawLFRuvj7F1mLgAmFXmVeFiAjKCasAkST495HKf6Ug28aRasRxyrnDQSJUj3Wj7kxvBirtDmAyR8cDfRQgRTWWYmyvG2NHwmF'
// const xpub = 'xpub6BxS8hHq2pPeFcdC5xg8pzdKqmPcK4xSspn2992gpHj4WvyLd3Y3URdUpXqECnkKWFu7cvJXUQiGRhNwAFno1NXSyU5FVtQmGPpDwsijfdH';
const TYPE_ADDRESS = {
    ecdsa: p => p.length > 32 ? blake2AsU8a(p) : p,
    ed25519: p => p,
    ethereum: p => p.length === 20 ? p : keccakAsU8a(secp256k1Expand(p)),
    sr25519: p => p
  };

// ColdWallet capabilities:
// generate address with given HDPath according to BIP32
// sign unsigned transaction
// verify signed transaction
class ColdWallet {
    hdkey;
    ss58Format;
    sigType;

    constructor (xprv, ss58Format) {
        this.ss58Format = ss58Format;
        this.hdkey = HdKey.fromExtendedKey(xprv);
        this.sigType = 'ecdsa'
    }

    generateAddress(index) {
        return this.getKeyringPair(index).address
    }

    verifySignature(message, signature, index) {
        const address = this.generateAddress(index);
        return signatureVerify(message, signature, address);
    }

    getKeyringPair(index) {
        const derivedKey = this.hdkey.derive(`m/44/354/0/0/${index}`);
        const keyring = new Keyring({ type: this.sigType, ss58Format: this.ss58Format});
        const pub_modified = TYPE_ADDRESS[this.sigType](derivedKey.publicKey)
        const keyPair = { publicKey: pub_modified, secretKey: derivedKey.privateKey };
        return keyring.createFromPair(keyPair, {}, this.sigType)
    }

    signTx(payload, index) {
        const keyringPair = this.getKeyringPair(index)
        const signature = keyringPair.sign(payload, { withType: true });
        const verified = this.verifySignature(payload, signature, index);
        console.log(verified);
        return u8aToHex(signature)
    }
}

const wallet = new ColdWallet(xprv, 42);

for (let i = 0; i <= 10; i++) {
    console.log(`index: ${i}: ${wallet.generateAddress(i)}`);
}

const result = wallet.signTx("0x04030068642b768476c83f685947efeeb40df8dd381dd6acef49614b268355ef41107302093d00a50318000e2400000b000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e6e4ca8d8c5a4d3184c7ca6ebe5108f477fcd88f3441f653df17c5b1a3fb8ab70", 0);
console.log("signedTx", result)