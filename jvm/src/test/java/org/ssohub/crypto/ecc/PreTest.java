/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

package org.ssohub.crypto.ecc;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.ssohub.crypto.ecc.Pre.KeyPair;
import static org.ssohub.crypto.ecc.Pre.SigningKeyPair;
import static org.ssohub.crypto.ecc.Pre.pre_schema1_DecryptLevel2;
import static org.ssohub.crypto.ecc.Pre.pre_schema1_Encrypt;
import static org.ssohub.crypto.ecc.Pre.pre_schema1_KeyGen;
import static org.ssohub.crypto.ecc.Pre.pre_schema1_MessageGen;
import static org.ssohub.crypto.ecc.Pre.pre_schema1_ReEncrypt;
import static org.ssohub.crypto.ecc.Pre.pre_schema1_ReKeyGen;
import static org.ssohub.crypto.ecc.Pre.pre_schema1_SigningKeyGen;

/**
 * @author aldenml
 */
public class PreTest {

    @Test
    void pre_schema1_re_encrypt_test() {
        // client A setup public/private keys and signing keys
        KeyPair keysA = pre_schema1_KeyGen();
        SigningKeyPair signingA = pre_schema1_SigningKeyGen();

        // client B setup public/private keys (signing keys are not used here)
        KeyPair keysB = pre_schema1_KeyGen();

        // proxy server setup signing keys
        SigningKeyPair signingProxy = pre_schema1_SigningKeyGen();

        // client A select a plaintext message, this message
        // in itself is random, but can be used as a seed
        // for symmetric encryption keys
        byte[] message = pre_schema1_MessageGen();

        // client A encrypts the message to itself, making it
        // possible to send this ciphertext to the proxy.
        byte[] ciphertextLevel1 = pre_schema1_Encrypt(message, keysA.pk, signingA);

        // client A sends ciphertextLevel1 to the proxy server and
        // eventually client A allows client B to see the encrypted
        // message, in this case the proxy needs to re-encrypt
        // ciphertextLevel1 (without ever knowing the plaintext).
        // In order to do that, the client A needs to create a re-encryption
        // key that the proxy can use to perform such operation.

        // client A creates a re-encryption key that the proxy can use
        // to re-encrypt the ciphertext (ciphertextLevel1) in order for
        // client B be able to recover the original message
        byte[] reEncKey = pre_schema1_ReKeyGen(keysA.sk, keysB.pk, signingA);

        // the proxy re-encrypt the ciphertext ciphertextLevel1 with such
        // a key that allows client B to recover the original message
        byte[] ciphertextLevel2 = pre_schema1_ReEncrypt(
            ciphertextLevel1,
            reEncKey,
            signingA.spk, keysB.pk,
            signingProxy
        );

        // client B is able to decrypt ciphertextLevel2 and the result
        // is the original plaintext message
        byte[] messageDecrypted = pre_schema1_DecryptLevel2(
            ciphertextLevel2,
            keysB.sk, signingProxy.spk
        );

        // now both client A and client B share the same plaintext message
        assertArrayEquals(messageDecrypted, message);
    }
}
