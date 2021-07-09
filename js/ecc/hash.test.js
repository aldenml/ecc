/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

import libecc_module from "./libecc.js";
import {
    str2bin,
    bin2hex
} from "./util.js";
import assert from "assert";

// Test vectors
// https://www.di-mgt.com.au/sha_testvectors.html

async function hash_ecc_hash_sha256(s) {
    const libecc = await libecc_module();
    let input = str2bin(s);
    let out = new Uint8Array(32);
    libecc.ecc_hash_sha256(out, input, input.length);
    return bin2hex(out);
}

describe("ecc_hash_sha256", () => {

    it("input abc", async () => {
        const r = await hash_ecc_hash_sha256(
            "abc"
        );
        assert.equal(r,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    });

    it("input empty string", async () => {
        const r = await hash_ecc_hash_sha256(
            ""
        );
        assert.equal(r,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    });

    it("input abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", async () => {
        const r = await hash_ecc_hash_sha256(
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        );
        assert.equal(r,
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    });

    it("input abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", async () => {
        const r = await hash_ecc_hash_sha256(
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
        );
        assert.equal(r,
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        );
    });
});

async function hash_ecc_hash_sha512(s) {
    const libecc = await libecc_module();
    let out = new Uint8Array(64);
    let input = str2bin(s);
    libecc.ecc_hash_sha512(out, input, input.length);
    return bin2hex(out);
}

describe("ecc_hash_sha512", () => {

    it("input abc", async () => {
        const r = await hash_ecc_hash_sha512(
            "abc"
        );
        assert.equal(r,
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    });

    it("input empty string", async () => {
        const r = await hash_ecc_hash_sha512(
            ""
        );
        assert.equal(r,
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    });

    it("input abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", async () => {
        const r = await hash_ecc_hash_sha512(
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        );
        assert.equal(r,
            "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"
        );
    });

    it("input abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", async () => {
        const r = await hash_ecc_hash_sha512(
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
        );
        assert.equal(r,
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
        );
    });
});
