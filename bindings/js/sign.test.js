/*
 * Copyright (c) 2022, Alden Torres
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

describe("ecc_sign_ed25519_SeedKeypair", () => {

    it("generates a keypair with a specified seed", async () => {
        const libecc = await libecc_module();
        const seed = hex2bin("829ee32a86b93d3766df28d8d77069fdc04e05b17fb095043c72a56d846d0372");
        let pk = new Uint8Array(libecc.ecc_sign_ed25519_PUBLICKEYSIZE);
        let sk = new Uint8Array(libecc.ecc_sign_ed25519_SECRETKEYSIZE);
        libecc.ecc_sign_ed25519_SeedKeyPair(pk, sk, seed);
        assert.strictEqual(bin2hex(pk), "b5ed5efc01b59d13708efa6186a6b11df026e1f5f66d417492c795bbc53211ee");
        assert.strictEqual(bin2hex(sk), "829ee32a86b93d3766df28d8d77069fdc04e05b17fb095043c72a56d846d0372b5ed5efc01b59d13708efa6186a6b11df026e1f5f66d417492c795bbc53211ee");
    });
});
