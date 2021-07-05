/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

package org.ssohub.crypto.ecc;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.ssohub.crypto.ecc.libecc.ecc_memzero;
import static org.ssohub.crypto.ecc.libecc.ecc_randombytes;

/**
 * @author aldenml
 */
public class UtilTest {

    @Test
    void memzero() {
        byte[] buf = new byte[100];
        ecc_randombytes(buf, buf.length);
        ecc_memzero(buf, buf.length);
        int count = 0;
        for (byte b : buf) {
            if (b == 0) count++;
        }
        assertEquals(buf.length, count);
    }

    @Test
    void randombytes() {
        byte[] buf = new byte[10];
        ecc_randombytes(buf, buf.length);
        int count = 0;
        for (byte b : buf) {
            if (b == 0) count++;
        }
        // what are the odds of having more than one 0 in a random of 10 elements
        assertTrue(count < 2);
    }
}
