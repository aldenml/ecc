/*
 * Copyright (c) 2021-2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

import libecc_module from "./libecc.js";
import assert from "assert";
import {
    bin2hex,
    hex2bin,
} from "./util.js";

describe("ecc_ed25519_random", () => {

    it("generates a random valid point", async () => {
        const libecc = await libecc_module();
        let p = new Uint8Array(32);
        libecc.ecc_ed25519_random(p);
        let r = libecc.ecc_ed25519_is_valid_point(p);
        assert.ok(r);
    });
});

describe("ecc_ed25519_is_valid_point", () => {

    it("test a random valid point", async () => {
        const libecc = await libecc_module();
        let p = new Uint8Array(32);
        libecc.ecc_ed25519_random(p);
        let r = libecc.ecc_ed25519_is_valid_point(p);
        assert.ok(r);
    });
});
