/*
 * Copyright (c) 2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

package org.ssohub.crypto.ecc;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.ssohub.crypto.ecc.Aead.chacha20poly1305Decrypt;
import static org.ssohub.crypto.ecc.Aead.chacha20poly1305Encrypt;

/**
 * @author aldenml
 */
public class AeadTest {

    @Test
    void test_chacha20poly1305() {

        Data key = Data.fromHex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0");
        Data nonce = Data.fromHex("000000000102030405060708");
        Data aad = Data.fromHex("f33388860000000000004e91");
        Data plaintext = Data.fromHex("496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d");
        Data ciphertext = Data.fromHex("64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709beead9d67890cbb22392336fea1851f38");

        Data plaintextEncrypted = chacha20poly1305Encrypt(
            plaintext,
            aad,
            nonce,
            key
        );

        Data ciphertextDecrypted = chacha20poly1305Decrypt(
            ciphertext,
            aad,
            nonce,
            key
        );

        assertEquals(plaintext, ciphertextDecrypted);
        assertEquals(ciphertext, plaintextEncrypted);
    }
}
