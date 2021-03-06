/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

package org.ssohub.crypto.ecc;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.ssohub.crypto.ecc.libecc.ecc_bls12_381_FP12SIZE;
import static org.ssohub.crypto.ecc.libecc.ecc_bls12_381_G1SIZE;
import static org.ssohub.crypto.ecc.libecc.ecc_bls12_381_G2SIZE;
import static org.ssohub.crypto.ecc.libecc.ecc_bls12_381_SCALARSIZE;
import static org.ssohub.crypto.ecc.libecc.ecc_bls12_381_fp12_mul;
import static org.ssohub.crypto.ecc.libecc.ecc_bls12_381_fp12_pow;
import static org.ssohub.crypto.ecc.libecc.ecc_bls12_381_fp12_random;
import static org.ssohub.crypto.ecc.libecc.ecc_bls12_381_g1_scalarmult_base;
import static org.ssohub.crypto.ecc.libecc.ecc_bls12_381_g2_scalarmult_base;
import static org.ssohub.crypto.ecc.libecc.ecc_bls12_381_pairing;
import static org.ssohub.crypto.ecc.libecc.ecc_bls12_381_pairing_final_verify;
import static org.ssohub.crypto.ecc.libecc.ecc_bls12_381_scalar_random;
import static org.ssohub.crypto.ecc.libecc.ecc_compare;
import static org.ssohub.crypto.ecc.libecc.ecc_randombytes;

/**
 * @author aldenml
 */
public class Bls12381Test {

    @Test
    public void test_ecc_bls12_381_fp12_pow() {
        byte[] a = new byte[ecc_bls12_381_FP12SIZE];
        ecc_bls12_381_fp12_random(a);

        byte[] r2 = new byte[ecc_bls12_381_FP12SIZE];
        ecc_bls12_381_fp12_pow(r2, a, 2);
        byte[] r3 = new byte[ecc_bls12_381_FP12SIZE];
        ecc_bls12_381_fp12_pow(r3, a, 3);

        byte[] x = new byte[ecc_bls12_381_FP12SIZE];
        ecc_bls12_381_fp12_mul(x, a, a);
        assertArrayEquals(x, r2);
        ecc_bls12_381_fp12_mul(a, x, a);
        assertArrayEquals(a, r3);
    }

    @Test
    public void test_ecc_bls12_381_pairing() {
        byte[] a = new byte[ecc_bls12_381_SCALARSIZE];
        byte[] b = new byte[ecc_bls12_381_SCALARSIZE];
        ecc_randombytes(a, 1);
        ecc_randombytes(b, 1);
        if (a[0] < 0) a[0] = (byte) -a[0];
        if (b[0] < 0) b[0] = (byte) -b[0];

        byte[] aP = new byte[ecc_bls12_381_G1SIZE];
        byte[] bQ = new byte[ecc_bls12_381_G2SIZE];

        ecc_bls12_381_g1_scalarmult_base(aP, a); // a * P
        ecc_bls12_381_g2_scalarmult_base(bQ, b); // b * Q

        byte[] pairing1 = new byte[ecc_bls12_381_FP12SIZE];
        ecc_bls12_381_pairing(pairing1, aP, bQ); // e(a * P, b * Q)

        byte[] one = new byte[ecc_bls12_381_SCALARSIZE];
        one[0] = 1; // 1 (one)

        byte[] P = new byte[ecc_bls12_381_G1SIZE];
        byte[] Q = new byte[ecc_bls12_381_G2SIZE];

        ecc_bls12_381_g1_scalarmult_base(P, one); // P
        ecc_bls12_381_g2_scalarmult_base(Q, one); // Q

        byte[] pairing2 = new byte[ecc_bls12_381_FP12SIZE];
        ecc_bls12_381_pairing(pairing2, P, Q); // e(P, Q)

        byte[] r = new byte[ecc_bls12_381_FP12SIZE];
        ecc_bls12_381_fp12_pow(r, pairing2, a[0] * b[0]);

        assertArrayEquals(pairing1, r);
    }

    @Test
    public void test_ecc_bls12_381_pairing_reverse_scalars() {
        byte[] a = new byte[ecc_bls12_381_SCALARSIZE];
        byte[] b = new byte[ecc_bls12_381_SCALARSIZE];
        ecc_randombytes(a, 1);
        ecc_randombytes(b, 1);

        byte[] aP = new byte[ecc_bls12_381_G1SIZE];
        byte[] bQ = new byte[ecc_bls12_381_G2SIZE];

        ecc_bls12_381_g1_scalarmult_base(aP, a); // a * P
        ecc_bls12_381_g2_scalarmult_base(bQ, b); // b * Q

        byte[] pairing1 = new byte[ecc_bls12_381_FP12SIZE];
        ecc_bls12_381_pairing(pairing1, aP, bQ); // e(a * P, b * Q)

        byte[] bP = new byte[ecc_bls12_381_G1SIZE];
        byte[] aQ = new byte[ecc_bls12_381_G2SIZE];

        ecc_bls12_381_g1_scalarmult_base(bP, b); // b * P
        ecc_bls12_381_g2_scalarmult_base(aQ, a); // a * Q

        byte[] pairing2 = new byte[ecc_bls12_381_FP12SIZE];
        ecc_bls12_381_pairing(pairing2, bP, aQ); // e(b * P, a * Q)

        // is e(a * P, b * Q) == e(b * P, a * Q) ?
        int r = ecc_compare(pairing1, pairing2, ecc_bls12_381_FP12SIZE);
        assertEquals(0, r);

        int v = ecc_bls12_381_pairing_final_verify(pairing1, pairing2);
        assertEquals(1, v);
    }

    @Test
    public void test_ecc_bls12_381_pairing_perform() {
        byte[] a = new byte[ecc_bls12_381_SCALARSIZE];
        byte[] b = new byte[ecc_bls12_381_SCALARSIZE];
        ecc_bls12_381_scalar_random(a);
        ecc_bls12_381_scalar_random(b);

        byte[] aP = new byte[ecc_bls12_381_G1SIZE];
        byte[] bQ = new byte[ecc_bls12_381_G2SIZE];

        ecc_bls12_381_g1_scalarmult_base(aP, a); // a * P
        ecc_bls12_381_g2_scalarmult_base(bQ, b); // b * Q

        byte[] pairing = new byte[ecc_bls12_381_FP12SIZE];
        ecc_bls12_381_pairing(pairing, aP, bQ); // e(a * P, b * Q)
    }
}
