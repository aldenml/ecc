/*
 * Copyright (c) 2021-2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

import {
    bin2hex,
    hex2bin,
    libecc_promise,
} from "./util.js";
import {
    oprf_BlindWithScalar,
    oprf_Evaluate,
    oprf_Finalize,
} from "./oprf.js";
import assert from "assert";

describe("OPRF(ristretto255, SHA-512)", () => {

    const skSm = hex2bin("5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e");

    it("input 00", async () => {
        await libecc_promise;

        const input = hex2bin("00");
        const info = hex2bin("74657374206b6579");
        const blind = hex2bin("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706");

        const blindedElement = oprf_BlindWithScalar(input, blind);
        const evaluationElement = oprf_Evaluate(skSm, blindedElement, info);
        const output = oprf_Finalize(input, blind, evaluationElement, info);

        assert.strictEqual(bin2hex(blindedElement), "609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c");
        assert.strictEqual(bin2hex(evaluationElement), "7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e");
        assert.strictEqual(bin2hex(output), "527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6");
    });

    it("input 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a", async () => {
        await libecc_promise;

        const input = hex2bin("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a");
        const info = hex2bin("74657374206b6579");
        const blind = hex2bin("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706");

        const blindedElement = oprf_BlindWithScalar(input, blind);
        const evaluationElement = oprf_Evaluate(skSm, blindedElement, info);
        const output = oprf_Finalize(input, blind, evaluationElement, info);

        assert.strictEqual(bin2hex(blindedElement), "da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418");
        assert.strictEqual(bin2hex(evaluationElement), "b4cbf5a4f1eeda5a63ce7b77c7d23f461db3fcab0dd28e4e17cecb5c90d02c25");
        assert.strictEqual(bin2hex(output), "f4a74c9c592497375e796aa837e907b1a045d34306a749db9f34221f7e750cb4f2a6413a6bf6fa5e19ba6348eb673934a722a7ede2e7621306d18951e7cf2c73");
    });
});
