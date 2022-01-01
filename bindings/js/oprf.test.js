/*
 * Copyright (c) 2021, Alden Torres
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

        assert.strictEqual(bin2hex(blindedElement), "744441a5d3ee12571a84d34812443eba2b6521a47265ad655f01e759b3dd7d35");
        assert.strictEqual(bin2hex(evaluationElement), "4254c503ee2013262473eec926b109b018d699b8dd954ee878bc17b159696353");
        assert.strictEqual(bin2hex(output), "9aef8983b729baacb7ecf1be98d1276ca29e7d62dbf39bc595be018b66b199119f18579a9ae96a39d7d506c9e00f75b433a870d76ba755a3e7196911fff89ff3");
    });

    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#appendix-A.1.1.2
    it("input 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a", async () => {
        const input = hex2bin("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a");
        const info = hex2bin("7465737420696e666f");
        const blind = hex2bin("5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037e50b");

        const blindedElement = await oprf_ristretto255_sha512_BlindWithScalar(input, blind);
        const evaluationElement = await oprf_ristretto255_sha512_Evaluate(skSm, blindedElement, info);
        const output = await oprf_ristretto255_sha512_Finalize(input, blind, evaluationElement, info);

        assert.strictEqual(bin2hex(blindedElement), "f4eeea4e1bcb2ec818ee2d5c1fcec56c24064a9ff4bea5b3dd6877800fc28e4d");
        assert.strictEqual(bin2hex(evaluationElement), "185dae43b6209dacbc41a62fd4889700d11eeeff4e83ffbc72d54daee7e25659");
        assert.strictEqual(bin2hex(output), "f556e2d83e576b4edc890472572d08f0d90d2ecc52a73b35b2a8416a72ff676549e3a83054fdf4fd16fe03e03bee7bb32cbd83c7ca212ea0d03b8996c2c268b2");
    });
});
