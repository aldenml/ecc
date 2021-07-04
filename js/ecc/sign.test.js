/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

import libecc_module from "./libecc.js";
import {
    hex2buf,
    buf2hex
} from "./util.js";
import assert from "assert";

describe("ecc_ed25519_sign_seed_keypair", () => {

    it("generates a keypair with a specified seed", async () => {
        const libecc = await libecc_module();
        const seed = hex2buf("829ee32a86b93d3766df28d8d77069fdc04e05b17fb095043c72a56d846d0372");
        let pk = new Uint8Array(32);
        let sk = new Uint8Array(64);
        libecc.ecc_ed25519_sign_seed_keypair(pk, sk, seed);
        assert.strictEqual(buf2hex(pk), "b5ed5efc01b59d13708efa6186a6b11df026e1f5f66d417492c795bbc53211ee");
        assert.strictEqual(buf2hex(sk), "829ee32a86b93d3766df28d8d77069fdc04e05b17fb095043c72a56d846d0372b5ed5efc01b59d13708efa6186a6b11df026e1f5f66d417492c795bbc53211ee");
    });
});
