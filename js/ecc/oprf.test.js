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
    ristretto255_sha512_BlindWithScalar,
} from "./oprf.js";
import assert from "assert";

describe("ristretto255_sha512_BlindWithScalar", () => {

    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#appendix-A.1.1.1
    it("input 00", async () => {
        let input = hex2buf("00");

        const blind = hex2buf("c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf8e03");
        const blindedElement = await ristretto255_sha512_BlindWithScalar(input, blind);

        assert.equal(buf2hex(blindedElement), "3c7f2d901c0d4f245503a186086fbdf5d8b4408432b25c5163e8b5a19c258348");
    });

    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#appendix-A.1.1.2
    it("input 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a", async () => {
        let input = hex2buf("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a");

        const blind = hex2buf("5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037e50b");
        const blindedElement = await ristretto255_sha512_BlindWithScalar(input, blind);

        assert.equal(buf2hex(blindedElement), "28a5e797b710f76d20a52507145fbf320a574ec2c8ab0e33e65dd2c277d0ee56");
    });
});
