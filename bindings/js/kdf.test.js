/*
 * Copyright (c) 2021-2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

import libecc_module from "./libecc.js";
import {
    bin2hex,
    hex2bin,
    str2bin,
    libecc_promise,
} from "./util.js";
import {
    kdf_argon2id,
} from "./kdf.js";
import assert from "assert";

describe("ecc_kdf_hkdf_sha256", () => {

    // https://datatracker.ietf.org/doc/html/rfc5869#appendix-A

    it("Test Case 1", async () => {
        const libecc = await libecc_module();
        const ikm = hex2bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        const salt = hex2bin("000102030405060708090a0b0c");
        const info = hex2bin("f0f1f2f3f4f5f6f7f8f9");
        const outLen = 42;

        let prk = new Uint8Array(32);
        libecc.ecc_kdf_hkdf_sha256_extract(prk, salt, salt.length, ikm, ikm.length);
        let okm = new Uint8Array(outLen);
        libecc.ecc_kdf_hkdf_sha256_expand(okm, prk, info, info.length, outLen);

        assert.strictEqual(bin2hex(prk), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        assert.strictEqual(bin2hex(okm), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    });

    it("Test Case 3", async () => {
        const libecc = await libecc_module();
        const ikm = hex2bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        const salt = hex2bin("");
        const info = hex2bin("");
        const outLen = 42;

        let prk = new Uint8Array(32);
        libecc.ecc_kdf_hkdf_sha256_extract(prk, salt, salt.length, ikm, ikm.length);
        let okm = new Uint8Array(outLen);
        libecc.ecc_kdf_hkdf_sha256_expand(okm, prk, info, info.length, outLen);

        assert.strictEqual(bin2hex(prk), "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
        assert.strictEqual(bin2hex(okm), "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
    });
});

describe("ecc_kdf_hkdf_sha512", () => {

    // https://github.com/jedisct1/libsodium/blob/master/test/default/kdf_hkdf.c
    // https://github.com/jedisct1/libsodium/blob/master/test/default/kdf_hkdf.exp

    it("test 1", async () => {
        const libecc = await libecc_module();

        const master_key_len = 66;
        let master_key = new Uint8Array(master_key_len);
        for (let i = 0; i < master_key_len; i++) {
            master_key[i] = i;
        }

        const salt_len = 77;
        let salt = new Uint8Array(salt_len);
        for (let i = 0; i < salt_len; i++) {
            salt[i] = ~i;
        }

        const context_len = 88;
        let context = new Uint8Array(context_len);
        for (let i = 0; i < context_len; i++) {
            context[i] = (i + 111);
        }

        let prk512 = new Uint8Array(64);
        libecc.ecc_kdf_hkdf_sha512_extract(prk512, salt, salt.length, master_key, master_key.length);

        assert.strictEqual(bin2hex(prk512), "2502bc897dc1b23f9f2d8c35d519c5280ea960bf9154ebb07d377a12a81a4794ea8bdc0cb6ec59ab3303f5cbd713027825715f8af2ac0203e560fd2e55f4ff2b");

        // i = 10
        const outLen = 10;
        let okm = new Uint8Array(outLen);
        context[0] = 10;
        libecc.ecc_kdf_hkdf_sha512_expand(okm, prk512, context, context.length, outLen);
        assert.strictEqual(bin2hex(okm), "046f63a1e2d606d7893e");
    });
});

describe("kdf_argon2id", () => {

    it("test 1", async () => {
        await libecc_promise;

        const password = str2bin("WelcomePassphrase");
        const salt = str2bin("abcdabcdabcdabcd");

        const out = kdf_argon2id(
            password,
            salt,
            32, 3,
            32,
        );

        assert.strictEqual(bin2hex(out), "38292f3f2cad1f2121bb8d236311e108d5d1826b9a04da31cb21c4791065079b");
    });

});
