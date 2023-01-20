/*
 * Copyright (c) 2021-2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

import {
    bin2hex,
    hex2bin,
} from "./util.js";
import {
    oprf_ristretto255_sha512_BlindWithScalar,
    oprf_ristretto255_sha512_Evaluate,
    oprf_ristretto255_sha512_Finalize,
} from "./oprf.js";
import assert from "assert";

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#appendix-A.1

describe("OPRF(ristretto255, SHA-512)", () => {

    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#appendix-A.1.1
    const skSm = hex2bin("74db8e13d2c5148a1181d57cc06debd730da4df1978b72ac18bc48992a0d2c0f");

    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#appendix-A.1.1.1
    it("input 00", async () => {
        const input = hex2bin("00");
        const info = hex2bin("7465737420696e666f");
        const blind = hex2bin("c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf8e03");

        const blindedElement = await oprf_ristretto255_sha512_BlindWithScalar(input, blind);
        const evaluationElement = await oprf_ristretto255_sha512_Evaluate(skSm, blindedElement, info);
        const output = await oprf_ristretto255_sha512_Finalize(input, blind, evaluationElement, info);

        assert.strictEqual(bin2hex(blindedElement), "b617363ffc96d9dd2309d3f8bd7345b5226eb9c863912cd86b8f34cf754c1b4e");
        assert.strictEqual(bin2hex(evaluationElement), "2a0c57e1dc889c729496670779647c56026fb0c1ce314c14f95726ff228c5461");
        assert.strictEqual(bin2hex(output), "be060dfe78216ed06ab2b716896f9215da964ebeec2ac23cbb4c158e8b9cbbea968a8061b23c04f350750ad1e5102c60593d679b6dcb22badb68f396fb7f6cc0");
    });

    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#appendix-A.1.1.2
    it("input 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a", async () => {
        const input = hex2bin("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a");
        const info = hex2bin("7465737420696e666f");
        const blind = hex2bin("5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037e50b");

        const blindedElement = await oprf_ristretto255_sha512_BlindWithScalar(input, blind);
        const evaluationElement = await oprf_ristretto255_sha512_Evaluate(skSm, blindedElement, info);
        const output = await oprf_ristretto255_sha512_Finalize(input, blind, evaluationElement, info);

        assert.strictEqual(bin2hex(blindedElement), "927e71dbbceecf21cd0631fcb7f15ca0143b9a15e587f84a35b8bd20bf2e0767");
        assert.strictEqual(bin2hex(evaluationElement), "505f2cd525a0ded45d41b9ae58e835beb0f25afcdf4de947ca5c5e4a73197910");
        assert.strictEqual(bin2hex(output), "4e45a1b18f93d220b2570fe9e4a49ef4ec108c8c43c15c26bd743d994a1d68eaf27e9fc05651ddfa36186022d22a036cca03ad27daca359f4a3d044d32b26455");
    });
});
