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

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-07#appendix-A.1

describe("OPRF(ristretto255, SHA-512)", () => {

    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-07#appendix-A.1.1
    const skSm = hex2bin("caeff69352df4905a9121a4997704ca8cee1524a110819eb87deba1a39ec1701");

    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-07#appendix-A.1.1.1
    it("input 00", async () => {
        const input = hex2bin("00");
        const blind = hex2bin("c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf8e03");

        const blindedElement = await oprf_ristretto255_sha512_BlindWithScalar(input, blind);
        const evaluationElement = await oprf_ristretto255_sha512_Evaluate(skSm, blindedElement);
        const output = await oprf_ristretto255_sha512_Finalize(input, blind, evaluationElement);

        assert.strictEqual(bin2hex(blindedElement), "fc20e03aff3a9de9b37e8d35886ade11ec7d85c2a1fb5bb0b1686c64e07ac467");
        assert.strictEqual(bin2hex(evaluationElement), "7c72cc293cd7d44c0b57c273f27befd598b132edc665694bdc9c42a4d3083c0a");
        assert.strictEqual(bin2hex(output), "e3a209dce2d3ea3d84fcddb282818caebb756a341e08a310d9904314f5392085d13c3f76339d745db0f46974a6049c3ea9546305af55d37760b2136d9b3f0134");
    });

    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-07#appendix-A.1.1.2
    it("input 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a", async () => {
        const input = hex2bin("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a");
        const blind = hex2bin("5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037e50b");

        const blindedElement = await oprf_ristretto255_sha512_BlindWithScalar(input, blind);
        const evaluationElement = await oprf_ristretto255_sha512_Evaluate(skSm, blindedElement);
        const output = await oprf_ristretto255_sha512_Finalize(input, blind, evaluationElement);

        assert.strictEqual(bin2hex(blindedElement), "483d4f39de5ff77fa0f9a0ad2334dd5bf87f2cda868539d21de67ce49e7d1536");
        assert.strictEqual(bin2hex(evaluationElement), "026f2758fc62f02a7ff95f35ec6f20186aa57c0274361655543ea235d7b2aa34");
        assert.strictEqual(bin2hex(output), "2c17dc3e9398dadb44bb2d3360c446302e99f1fe0ec40f0b1ad25c9cf002be1e4b41b4900ef056537fe8c14532ccea4d796f5feab9541af48057d83c0db86fe9");
    });
});
