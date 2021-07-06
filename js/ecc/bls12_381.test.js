/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

import libecc_module from "./libecc.js";
import {
    hex2bin,
    bin2hex,
} from "./util.js";
import assert from "assert";

describe("ecc_bls12_381_keygen", () => {

    // TODO: find vector tests
    it("test 1", async () => {
        const libecc = await libecc_module();
        const ikm = hex2bin("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04");
        let sk = new Uint8Array(32);
        libecc.ecc_bls12_381_keygen(sk, ikm, ikm.length);
        assert.strictEqual(bin2hex(sk), "7050b4223168ae407dee804d461fc3dbfe53f5dc5218debb8fab6379d559730d");
    });
});
