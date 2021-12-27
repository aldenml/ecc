/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

import libecc_module from "./libecc.js";
import {
    hex2bin,
    bin2hex,
} from "./util.js";
import assert from "assert";

describe("ecc_bls12_381_fp12_pow", () => {

    it("test", async () => {
        const libecc = await libecc_module();

        const a = new Uint8Array(576);
        libecc.ecc_bls12_381_fp12_random(a);

        const r2 = new Uint8Array(576);
        libecc.ecc_bls12_381_fp12_pow(r2, a, 2);
        const r3 = new Uint8Array(576);
        libecc.ecc_bls12_381_fp12_pow(r3, a, 3);

        const x = new Uint8Array(576);
        libecc.ecc_bls12_381_fp12_mul(x, a, a);
        assert.deepStrictEqual(x, r2);
        libecc.ecc_bls12_381_fp12_mul(a, x, a);
        assert.deepStrictEqual(a, r3);
    });
});

describe("ecc_bls12_381_pairing", () => {

    it("test", async () => {
        const libecc = await libecc_module();

        const a = new Uint8Array(32);
        const b = new Uint8Array(32);
        libecc.ecc_randombytes(a, 1);
        libecc.ecc_randombytes(b, 1);

        const aP = new Uint8Array(96);
        const bQ = new Uint8Array(192);

        libecc.ecc_bls12_381_g1_scalarmult_base(aP, a); // a * P
        libecc.ecc_bls12_381_g2_scalarmult_base(bQ, b); // b * Q

        const pairing1 = new Uint8Array(576);
        libecc.ecc_bls12_381_pairing(pairing1, aP, bQ); // e(a * P, b * Q)

        const one = new Uint8Array(32);
        one[0] = 1; // 1 (one)

        const P = new Uint8Array(96);
        const Q = new Uint8Array(192);

        libecc.ecc_bls12_381_g1_scalarmult_base(P, one); // P
        libecc.ecc_bls12_381_g2_scalarmult_base(Q, one); // Q

        const pairing2 = new Uint8Array(576);
        libecc.ecc_bls12_381_pairing(pairing2, P, Q); // e(P, Q)

        const r = new Uint8Array(576);
        libecc.ecc_bls12_381_fp12_pow(r, pairing2, a[0] * b[0]);

        assert.deepStrictEqual(pairing1, r);
    });

    it("test reverse scalars", async () => {
        const libecc = await libecc_module();

        const a = new Uint8Array(32);
        const b = new Uint8Array(32);
        libecc.ecc_randombytes(a, 1);
        libecc.ecc_randombytes(b, 1);

        const aP = new Uint8Array(96);
        const bQ = new Uint8Array(192);

        libecc.ecc_bls12_381_g1_scalarmult_base(aP, a); // a * P
        libecc.ecc_bls12_381_g2_scalarmult_base(bQ, b); // b * Q

        const pairing1 = new Uint8Array(576);
        libecc.ecc_bls12_381_pairing(pairing1, aP, bQ); // e(a * P, b * Q)

        const bP = new Uint8Array(96);
        const aQ = new Uint8Array(192);

        libecc.ecc_bls12_381_g1_scalarmult_base(bP, b); // b * P
        libecc.ecc_bls12_381_g2_scalarmult_base(aQ, a); // a * Q

        const pairing2 = new Uint8Array(576);
        libecc.ecc_bls12_381_pairing(pairing2, bP, aQ); // e(b * P, a * Q)

        // is e(a * P, b * Q) == e(b * P, a * Q) ?
        assert.deepStrictEqual(pairing1, pairing2);

        const v = libecc.ecc_bls12_381_pairing_final_verify(pairing1, pairing2);
        assert.strictEqual(v, 1);
    });

    it("calculate a pairing", async () => {
        const libecc = await libecc_module();

        const a = new Uint8Array(32);
        const b = new Uint8Array(32);
        libecc.ecc_bls12_381_scalar_random(a);
        libecc.ecc_bls12_381_scalar_random(b);

        const aP = new Uint8Array(96);
        const bQ = new Uint8Array(192);

        libecc.ecc_bls12_381_g1_scalarmult_base(aP, a); // a * P
        libecc.ecc_bls12_381_g2_scalarmult_base(bQ, b); // b * Q

        const pairing = new Uint8Array(576);
        libecc.ecc_bls12_381_pairing(pairing, aP, bQ); // e(a * P, b * Q)
    });
});

// describe("ecc_bls12_381_sign_keygen", () => {
//
//     // TODO: find vector tests
//     it("test 1", async () => {
//         const libecc = await libecc_module();
//         const ikm = hex2bin("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04");
//         let sk = new Uint8Array(32);
//         libecc.ecc_bls12_381_sign_keygen(sk, ikm, ikm.length);
//         assert.strictEqual(bin2hex(sk), "7050b4223168ae407dee804d461fc3dbfe53f5dc5218debb8fab6379d559730d");
//     });
// });
