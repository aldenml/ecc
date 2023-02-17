/*
 * Copyright (c) 2022-2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

package org.ssohub.crypto.ecc;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.ssohub.crypto.ecc.Util.bin2hex;
import static org.ssohub.crypto.ecc.Util.hex2bin;

/**
 * @author aldenml
 */
public class OprfTest {

    @Test
    void oprf_ristretto255_sha512_base_test1() {
        byte[] skSm = hex2bin("5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e");
        byte[] input = hex2bin("00");
        byte[] blind = hex2bin("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706");

        byte[] blindedElement = Oprf.oprf_ristretto255_sha512_BlindWithScalar(
            input,
            blind
        );

        assertEquals("609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c", bin2hex(blindedElement));

        byte[] evaluationElement = Oprf.oprf_ristretto255_sha512_Evaluate(
            skSm,
            blindedElement
        );

        assertEquals("7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e", bin2hex(evaluationElement));

        byte[] output = Oprf.oprf_ristretto255_sha512_Finalize(
            input,
            blind,
            evaluationElement
        );

        assertEquals("527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6", bin2hex(output));
    }

    @Test
    void oprf_ristretto255_sha512_base_test2() {
        byte[] skSm = hex2bin("5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e");
        byte[] input = hex2bin("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a");
        byte[] blind = hex2bin("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706");

        byte[] blindedElement = Oprf.oprf_ristretto255_sha512_BlindWithScalar(
            input,
            blind
        );

        assertEquals("da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418", bin2hex(blindedElement));

        byte[] evaluationElement = Oprf.oprf_ristretto255_sha512_Evaluate(
            skSm,
            blindedElement
        );

        assertEquals("b4cbf5a4f1eeda5a63ce7b77c7d23f461db3fcab0dd28e4e17cecb5c90d02c25", bin2hex(evaluationElement));

        byte[] output = Oprf.oprf_ristretto255_sha512_Finalize(
            input,
            blind,
            evaluationElement
        );

        assertEquals("f4a74c9c592497375e796aa837e907b1a045d34306a749db9f34221f7e750cb4f2a6413a6bf6fa5e19ba6348eb673934a722a7ede2e7621306d18951e7cf2c73", bin2hex(output));
    }
}
