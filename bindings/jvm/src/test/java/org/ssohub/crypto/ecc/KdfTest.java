/*
 * Copyright (c) 2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

package org.ssohub.crypto.ecc;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.ssohub.crypto.ecc.Kdf.argon2id;

/**
 * @author aldenml
 */
public class KdfTest {

    @Test
    void test_argon2id() {
        Data password = new Data(Util.str2bin("WelcomePassphrase"));
        Data salt = new Data(Util.str2bin("abcdabcdabcdabcd"));

        Data out = argon2id(
            password,
            salt,
            32, 3,
            32
        );

        assertEquals("38292f3f2cad1f2121bb8d236311e108d5d1826b9a04da31cb21c4791065079b", out.toHex());
    }
}
