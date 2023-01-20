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
} from "./util.js";
import assert from "assert";

describe("HMAC-SHA-256, HMAC-SHA-512", () => {

    // https://datatracker.ietf.org/doc/html/rfc4231

    // https://datatracker.ietf.org/doc/html/rfc4231#section-4.2
    it("Test Case 1", async () => {
        const libecc = await libecc_module();
        const key = hex2bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        const data = hex2bin("4869205468657265");

        let out256 = new Uint8Array(32);
        let out512 = new Uint8Array(64);
        libecc.ecc_mac_hmac_sha256(out256, data, data.length, key, key.length);
        libecc.ecc_mac_hmac_sha512(out512, data, data.length, key, key.length);

        assert.strictEqual(bin2hex(out256), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        assert.strictEqual(bin2hex(out512), "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
    });

    // https://datatracker.ietf.org/doc/html/rfc4231#section-4.3
    it("Test Case 2", async () => {
        const libecc = await libecc_module();
        const key = hex2bin("4a656665");
        const data = hex2bin("7768617420646f2079612077616e7420666f72206e6f7468696e673f");

        let out256 = new Uint8Array(32);
        let out512 = new Uint8Array(64);
        libecc.ecc_mac_hmac_sha256(out256, data, data.length, key, key.length);
        libecc.ecc_mac_hmac_sha512(out512, data, data.length, key, key.length);

        assert.strictEqual(bin2hex(out256), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        assert.strictEqual(bin2hex(out512), "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
    });
});
