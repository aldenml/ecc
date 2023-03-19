/*
 * Copyright (c) 2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

package org.ssohub.crypto.ecc;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.ssohub.crypto.ecc.Hash.sha256;
import static org.ssohub.crypto.ecc.Hash.sha512;

/**
 * @author aldenml
 */
public class HashTest {

    @Test
    void test_sha256() {
        Data input = new Data(Util.str2bin("abc"));

        Data digest = sha256(input);

        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", digest.toHex());
    }

    @Test
    void test_sha512() {
        Data input = new Data(Util.str2bin("abc"));

        Data digest = sha512(input);

        assertEquals("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", digest.toHex());
    }
}
