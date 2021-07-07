/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

package org.ssohub.crypto.ecc;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.ssohub.crypto.ecc.Util.bin2hex;
import static org.ssohub.crypto.ecc.Util.str2bin;
import static org.ssohub.crypto.ecc.libecc.ecc_h2c_expand_message_xmd_sha512;

/**
 * @author aldenml
 */
public class H2cTest {

    byte[] dst = str2bin("QUUX-V01-CS02-with-expander");
    int dst_len = 27;

    @Test
    void ecc_expand_message_xmd_sha512_test1() {
        byte[] msg = new byte[0];
        int msg_len = 0;
        int len_in_bytes = 0x20;
        byte[] uniform_bytes = new byte[0x20];

        ecc_h2c_expand_message_xmd_sha512(
            uniform_bytes,
            msg, msg_len,
            dst, dst_len,
            len_in_bytes
        );

        String hex = bin2hex(uniform_bytes);
        assertEquals("2eaa1f7b5715f4736e6a5dbe288257abf1faa028680c1d938cd62ac699ead642", hex);
    }

    @Test
    void ecc_expand_message_xmd_sha512_test1_null() {
        byte[] msg = null;
        int msg_len = 0;
        int len_in_bytes = 0x20;
        byte[] uniform_bytes = new byte[0x20];

        ecc_h2c_expand_message_xmd_sha512(
            uniform_bytes,
            msg, msg_len,
            dst, dst_len,
            len_in_bytes
        );

        String hex = bin2hex(uniform_bytes);
        assertEquals("2eaa1f7b5715f4736e6a5dbe288257abf1faa028680c1d938cd62ac699ead642", hex);
    }

    @Test
    void ecc_expand_message_xmd_sha512_test2() {
        byte[] msg = str2bin("abc");
        int msg_len = 3;
        int len_in_bytes = 0x20;
        byte[] uniform_bytes = new byte[0x20];

        ecc_h2c_expand_message_xmd_sha512(
            uniform_bytes,
            msg, msg_len,
            dst, dst_len,
            len_in_bytes
        );

        String hex = bin2hex(uniform_bytes);
        assertEquals("0eeda81f69376c80c0f8986496f22f21124cb3c562cf1dc608d2c13005553b0f", hex);
    }

    @Test
    void ecc_expand_message_xmd_sha512_test3() {
        byte[] msg = str2bin("abcdef0123456789");
        int msg_len = 16;
        int len_in_bytes = 0x20;
        byte[] uniform_bytes = new byte[0x20];

        ecc_h2c_expand_message_xmd_sha512(
            uniform_bytes,
            msg, msg_len,
            dst, dst_len,
            len_in_bytes
        );

        String hex = bin2hex(uniform_bytes);
        assertEquals("2e375fc05e05e80dbf3083796fde2911789d9e8847e1fcebf4ca4b36e239b338", hex);
    }

    @Test
    void ecc_expand_message_xmd_sha512_test4() {
        byte[] msg = str2bin(
            "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" +
                "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" +
                "qqqqqqqqqqqqqqqqqqqqqqqqq"
        );
        int msg_len = 133;
        int len_in_bytes = 0x20;
        byte[] uniform_bytes = new byte[0x20];

        ecc_h2c_expand_message_xmd_sha512(
            uniform_bytes,
            msg, msg_len,
            dst, dst_len,
            len_in_bytes
        );

        String hex = bin2hex(uniform_bytes);
        assertEquals("c37f9095fe7fe4f01c03c3540c1229e6ac8583b07510085920f62ec66acc0197", hex);
    }

    @Test
    void ecc_expand_message_xmd_sha512_test5() {
        byte[] msg = new byte[0];
        int msg_len = 0;
        int len_in_bytes = 0x80;
        byte[] uniform_bytes = new byte[0x80];

        ecc_h2c_expand_message_xmd_sha512(
            uniform_bytes,
            msg, msg_len,
            dst, dst_len,
            len_in_bytes
        );

        String hex = bin2hex(uniform_bytes);
        assertEquals(
            "0687ce02eba5eb3faf1c3c539d1f04babd3c0f420edae244" +
                "eeb2253b6c6d6865145c31458e824b4e87ca61c3442dc7c8c9872b" +
                "0b7250aa33e0668ccebbd2b386de658ca11a1dcceb51368721ae6d" +
                "cd2d4bc86eaebc4e0d11fa02ad053289c9b28a03da6c942b2e12c1" +
                "4e88dbde3b0ba619d6214f47212b628f3e1b537b66efcf",
            hex
        );
    }

    @Test
    void ecc_expand_message_xmd_sha512_test6() {
        byte[] msg = str2bin("abc");
        int msg_len = 3;
        int len_in_bytes = 0x80;
        byte[] uniform_bytes = new byte[0x80];

        ecc_h2c_expand_message_xmd_sha512(
            uniform_bytes,
            msg, msg_len,
            dst, dst_len,
            len_in_bytes
        );

        String hex = bin2hex(uniform_bytes);
        assertEquals(
            "779ae4fd8a92f365e4df96b9fde97b40486bb005c1a2096c" +
                "86f55f3d92875d89045fbdbc4a0e9f2d3e1e6bcd870b2d7131d868" +
                "225b6fe72881a81cc5166b5285393f71d2e68bb0ac603479959370" +
                "d06bdbe5f0d8bfd9af9494d1e4029bd68ab35a561341dd3f866b3e" +
                "f0c95c1fdfaab384ce24a23427803dda1db0c7d8d5344a",
            hex
        );
    }

    @Test
    void ecc_expand_message_xmd_sha512_test7() {
        byte[] msg = str2bin("abcdef0123456789");
        int msg_len = 16;
        int len_in_bytes = 0x80;
        byte[] uniform_bytes = new byte[0x80];

        ecc_h2c_expand_message_xmd_sha512(
            uniform_bytes,
            msg, msg_len,
            dst, dst_len,
            len_in_bytes
        );

        String hex = bin2hex(uniform_bytes);
        assertEquals(
            "f0953d28846a50e9f88b7ae35b643fc43733c9618751b569" +
                "a73960c655c068db7b9f044ad5a40d49d91c62302eaa26163c12ab" +
                "fa982e2b5d753049e000adf7630ae117aeb1fb9b61fc724431ac68" +
                "b369e12a9481b4294384c3c890d576a79264787bc8076e7cdabe50" +
                "c044130e480501046920ff090c1a091c88391502f0fbac",
            hex
        );
    }

    @Test
    void ecc_expand_message_xmd_sha512_test8() {
        byte[] msg = str2bin(
            "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" +
                "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" +
                "qqqqqqqqqqqqqqqqqqqqqqqqq"
        );
        int msg_len = 133;
        int len_in_bytes = 0x80;
        byte[] uniform_bytes = new byte[0x80];

        ecc_h2c_expand_message_xmd_sha512(
            uniform_bytes,
            msg, msg_len,
            dst, dst_len,
            len_in_bytes
        );

        String hex = bin2hex(uniform_bytes);
        assertEquals(
            "64d3e59f0bc3c5e653011c914b419ba8310390a9585311fd" +
                "db26791d26663bd71971c347e1b5e88ba9274d2445ed9dcf48eea9" +
                "528d807b7952924159b7c27caa4f25a2ea94df9508e70a7012dfce" +
                "0e8021b37e59ea21b80aa9af7f1a1f2efa4fbe523c4266ce7d342a" +
                "caacd438e452c501c131156b4945515e9008d2b155c258",
            hex
        );
    }
}
