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

describe("ecc_sign_ed25519_seed_keypair", () => {

    it("generates a keypair with a specified seed", async () => {
        const libecc = await libecc_module();
        const seed = hex2bin("829ee32a86b93d3766df28d8d77069fdc04e05b17fb095043c72a56d846d0372");
        let pk = new Uint8Array(32);
        let sk = new Uint8Array(64);
        libecc.ecc_sign_ed25519_seed_keypair(pk, sk, seed);
        assert.strictEqual(bin2hex(pk), "b5ed5efc01b59d13708efa6186a6b11df026e1f5f66d417492c795bbc53211ee");
        assert.strictEqual(bin2hex(sk), "829ee32a86b93d3766df28d8d77069fdc04e05b17fb095043c72a56d846d0372b5ed5efc01b59d13708efa6186a6b11df026e1f5f66d417492c795bbc53211ee");
    });
});
