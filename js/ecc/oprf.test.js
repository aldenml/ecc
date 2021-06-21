/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

import {
    buf2hex,
    hex2buf,
} from "./util.js";
import {
    oprf_ristretto255_sha512_BlindWithScalar,
    oprf_ristretto255_sha512_HashToGroup,
    oprf_ristretto255_sha512_Evaluate,
    oprf_ristretto255_sha512_Finalize,
} from "./oprf.js";
import assert from "assert";

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#appendix-A.1

describe("OPRF(ristretto255, SHA-512)", () => {

    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#appendix-A.1.1
    const seed = hex2buf("aca1ae53bec831a1279b75ec6091b23d28034b59f77abeb0fa8f6d1a01340234");
    const skSm = hex2buf("758cbac0e1eb4265d80f6e6489d9a74d788f7ddeda67d7fb3c08b08f44bda30a");

    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#appendix-A.1.1.1
    it("input 00", async () => {
        const input = hex2buf("00");
        const blind = hex2buf("c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf8e03");

        const blindedElement = await oprf_ristretto255_sha512_BlindWithScalar(input, blind);
        const evaluationElement = await oprf_ristretto255_sha512_Evaluate(skSm, blindedElement);
        const output = await oprf_ristretto255_sha512_Finalize(input, blind, evaluationElement);

        assert.equal(buf2hex(blindedElement), "3c7f2d901c0d4f245503a186086fbdf5d8b4408432b25c5163e8b5a19c258348");
        assert.equal(buf2hex(evaluationElement), "fc6c2b854553bf1ed6674072ed0bde1a9911e02b4bd64aa02cfb428f30251e77");
        assert.equal(buf2hex(output), "d8ed12382086c74564ae19b7a2b5ed9bdc52656d1fc151faaae51aaba86291e8df0b2143a92f24d44d5efd0892e2e26721d27d88745343493634a66d3a925e3a");
    });

    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#appendix-A.1.1.2
    it("input 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a", async () => {
        const input = hex2buf("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a");
        const blind = hex2buf("5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037e50b");

        const blindedElement = await oprf_ristretto255_sha512_BlindWithScalar(input, blind);
        const evaluationElement = await oprf_ristretto255_sha512_Evaluate(skSm, blindedElement);
        const output = await oprf_ristretto255_sha512_Finalize(input, blind, evaluationElement);

        assert.equal(buf2hex(blindedElement), "28a5e797b710f76d20a52507145fbf320a574ec2c8ab0e33e65dd2c277d0ee56");
        assert.equal(buf2hex(evaluationElement), "345e140b707257ae83d4911f7ead3177891e7a62c54097732802c4c7a98ab25a");
        assert.equal(buf2hex(output), "4d5f4221b5ebfd4d1a9dd54830e1ed0bce5a8f30a792723a6fddfe6cfe9f86bb1d95a3725818aeb725eb0b1b52e01ee9a72f47042372ef66c307770054d674fc");
    });
});
