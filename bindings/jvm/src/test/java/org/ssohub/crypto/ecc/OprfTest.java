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
        byte[] skSm = hex2bin("74db8e13d2c5148a1181d57cc06debd730da4df1978b72ac18bc48992a0d2c0f");
        byte[] input = hex2bin("00");
        byte[] blind = hex2bin("c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf8e03");

        byte[] blindedElement = Oprf.oprf_ristretto255_sha512_BlindWithScalar(
            input,
            blind
        );

        assertEquals("b617363ffc96d9dd2309d3f8bd7345b5226eb9c863912cd86b8f34cf754c1b4e", bin2hex(blindedElement));

        byte[] evaluationElement = Oprf.oprf_ristretto255_sha512_Evaluate(
            skSm,
            blindedElement
        );

        assertEquals("2a0c57e1dc889c729496670779647c56026fb0c1ce314c14f95726ff228c5461", bin2hex(evaluationElement));

        byte[] output = Oprf.oprf_ristretto255_sha512_Finalize(
            input,
            blind,
            evaluationElement
        );

        assertEquals("be060dfe78216ed06ab2b716896f9215da964ebeec2ac23cbb4c158e8b9cbbea968a8061b23c04f350750ad1e5102c60593d679b6dcb22badb68f396fb7f6cc0", bin2hex(output));
    }

    @Test
    void oprf_ristretto255_sha512_base_test2() {
        byte[] skSm = hex2bin("74db8e13d2c5148a1181d57cc06debd730da4df1978b72ac18bc48992a0d2c0f");
        byte[] input = hex2bin("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a");
        byte[] blind = hex2bin("5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037e50b");

        byte[] blindedElement = Oprf.oprf_ristretto255_sha512_BlindWithScalar(
            input,
            blind
        );

        assertEquals("927e71dbbceecf21cd0631fcb7f15ca0143b9a15e587f84a35b8bd20bf2e0767", bin2hex(blindedElement));

        byte[] evaluationElement = Oprf.oprf_ristretto255_sha512_Evaluate(
            skSm,
            blindedElement
        );

        assertEquals("505f2cd525a0ded45d41b9ae58e835beb0f25afcdf4de947ca5c5e4a73197910", bin2hex(evaluationElement));

        byte[] output = Oprf.oprf_ristretto255_sha512_Finalize(
            input,
            blind,
            evaluationElement
        );

        assertEquals("4e45a1b18f93d220b2570fe9e4a49ef4ec108c8c43c15c26bd743d994a1d68eaf27e9fc05651ddfa36186022d22a036cca03ad27daca359f4a3d044d32b26455", bin2hex(output));
    }
}
