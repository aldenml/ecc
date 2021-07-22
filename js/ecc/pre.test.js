/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

import {
    pre_schema1_KeyGen,
    pre_schema1_SigningKeyGen,
    pre_schema1_MessageGen,
    pre_schema1_Encrypt,
    pre_schema1_ReKeyGen,
    pre_schema1_ReEncrypt,
    pre_schema1_DecryptLevel2,
} from "./pre.js"
import assert from "assert";

describe("PRE proxy re-encryption", () => {

    it("demo test", async () => {
        // client A setup public/private keys and signing keys
        const keysA = await pre_schema1_KeyGen();
        const signingA = await pre_schema1_SigningKeyGen();

        // client B setup public/private keys (signing keys are not used here)
        const keysB = await pre_schema1_KeyGen();

        // proxy server setup signing keys
        const signingProxy = await pre_schema1_SigningKeyGen();

        // client A select a plaintext message, this message
        // in itself is random, but can be used as a seed
        // for symmetric encryption keys
        const message = await pre_schema1_MessageGen();

        // client A encrypts the message to itself, making it
        // possible to send this ciphertext to the proxy.
        const ciphertextLevel1 = await pre_schema1_Encrypt(message, keysA.pk, signingA);

        // client A sends ciphertextLevel1 to the proxy server and
        // eventually client A allows client B to see the encrypted
        // message, in this case the proxy needs to re-encrypt
        // ciphertextLevel1 (without ever knowing the plaintext).
        // In order to do that, the client A needs to create a re-encryption
        // key that the proxy can use to perform such operation.

        // client A creates a re-encryption key that the proxy can use
        // to re-encrypt the ciphertext (ciphertextLevel1) in order for
        // client B be able to recover the original message
        const reEncKey = await pre_schema1_ReKeyGen(keysA.sk, keysB.pk, signingA);

        // the proxy re-encrypt the ciphertext ciphertextLevel1 with such
        // a key that allows client B to recover the original message
        const ciphertextLevel2 = await pre_schema1_ReEncrypt(
            ciphertextLevel1,
            reEncKey,
            signingA.spk, keysB.pk,
            signingProxy
        );

        // client B is able to decrypt ciphertextLevel2 and the result
        // is the original plaintext message
        const messageDecrypted = await pre_schema1_DecryptLevel2(
            ciphertextLevel2,
            keysB.sk, signingProxy.spk
        );

        // now both client A and client B share the same plaintext message
        assert.deepStrictEqual(messageDecrypted, message);
    });
});
