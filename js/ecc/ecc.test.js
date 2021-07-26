/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

import libecc_module from "./libecc.js";
import assert from "assert";

describe("ecc_randombytes", () => {

    it("fills an array of 128 bytes", async () => {
        const libecc = await libecc_module();
        let buf = new Uint8Array(128);
        libecc.ecc_randombytes(buf);
    });
});

describe("ecc_compare", () => {

    it("compare a == b", async () => {
        const libecc = await libecc_module();
        let a = Uint8Array.of(1, 2, 3);
        let b = Uint8Array.of(1, 2, 3);
        let r = libecc.ecc_compare(a, b, 3);
        assert.equal(r, 0);
    });

    it("compare a < b", async () => {
        const libecc = await libecc_module();
        let a = Uint8Array.of(1, 2, 3);
        let b = Uint8Array.of(1, 4, 3);
        let r = libecc.ecc_compare(a, b, 3);
        assert.equal(r, -1);
    });

    it("compare a > b", async () => {
        const libecc = await libecc_module();
        let a = Uint8Array.of(1, 4, 3);
        let b = Uint8Array.of(1, 3, 3);
        let r = libecc.ecc_compare(a, b, 3);
        assert.equal(r, 1);
    });
});

describe("ecc_is_zero", () => {

    it("test a zero vector", async () => {
        const libecc = await libecc_module();
        let n = Uint8Array.of(0, 0, 0);
        let r = libecc.ecc_is_zero(n, 3);
        assert.ok(r);
    });

    it("test a non zero vector", async () => {
        const libecc = await libecc_module();
        let n = Uint8Array.of(1, 2, 3);
        let r = libecc.ecc_is_zero(n, 3);
        assert.ok(!r);
    });
});
