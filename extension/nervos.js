import { Buffer } from 'buffer';
import { ec as EC } from "elliptic";
import { utils } from "@ckb-lumos/base";
import { initializeConfig, predefined } from '@ckb-lumos/config-manager';
import { encodeToAddress } from '@ckb-lumos/helpers';

global.Buffer = Buffer;
const ec = new EC("secp256k1");

function assertPrivateKey(privateKey) {
    utils.assertHexString("privateKey", privateKey);
    if (privateKey.length !== 66) {
        throw new Error(`privateKey must be length of 32 bytes!`);
    }
}

function assertPublicKey(publicKey, debugPath) {
    debugPath = debugPath || "publicKey";
    utils.assertHexString(debugPath, publicKey);
    if (publicKey.length !== 68) {
      throw new Error(`publicKey must be length of 33 bytes!`);
    }
  }

export function privateToPublic(privateKey) {
    let pkBuffer = privateKey;
    if (typeof privateKey === "string") {
        assertPrivateKey(privateKey);
        pkBuffer = Buffer.from(privateKey.slice(2), "hex");
    }
    if (pkBuffer.length !== 32) {
        throw new Error("Private key must be 32 bytes!");
    }

    const publickey = ec.keyFromPrivate(pkBuffer).getPublic(true, "hex");
    if (typeof privateKey === "string") {
        return "0x" + publickey;
    }
    return Buffer.from(publickey, "hex");
}

export function publicKeyToBlake160(publicKey) {
    assertPublicKey(publicKey);

    const blake160 = new utils.CKBHasher()
        .update(publicKey)
        .digestHex()
        .slice(0, 42);

    return blake160;
}

export function privateKeyToBlake160(privateKey) {
    const publicKey = privateToPublic(privateKey);
    return publicKeyToBlake160(publicKey);
}

export function getCkbAddress(privateKey) {
    const config = predefined.LINA;
    initializeConfig(config);
    const pk = privateToPublic(privateKey);
    const blake160 = publicKeyToBlake160(pk);

    // ref: https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0026-anyone-can-pay/0026-anyone-can-pay.md#script-structure
    // 08: minimal transfer = 1 CKB
    const script = {
        codeHash: config.SCRIPTS.ANYONE_CAN_PAY.CODE_HASH,
        hashType: "type",
        args: `${blake160}08`,
    };
    const addr = encodeToAddress(script, config);
    return addr;
}
