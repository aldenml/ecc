/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

package org.ssohub.crypto.ecc;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.ssohub.crypto.ecc.libecc.ecc_bls12_381_FP12SIZE;
import static org.ssohub.crypto.ecc.libecc.ecc_bls12_381_G1SIZE;
import static org.ssohub.crypto.ecc.libecc.ecc_bls12_381_G2SIZE;
import static org.ssohub.crypto.ecc.libecc.ecc_bls12_381_SCALARSIZE;
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
    public void ecc_bls12_381_pairing_test_reverse_scalars() {
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
    public void ecc_bls12_381_pairing_test_perform() {
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
