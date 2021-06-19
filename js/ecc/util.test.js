/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

import * as util from "./util.js";
import assert from "assert";

describe("str2buf", () => {

    it("input abcd", async () => {
        let buf = util.str2buf("abcd");
        assert.deepEqual(buf, Uint8Array.of(97, 98, 99, 100));
    });
});

describe("buf2hex", () => {

    it("input abcd", async () => {
        let buf = util.str2buf("abcd");
        assert.equal(util.buf2hex(buf), "61626364");
    });
});

describe("I2OSP/OS2IP", () => {

    it("input x=1, xLen=1", async () => {
        let buf = util.I2OSP(1, 2);
        assert.deepEqual(buf, Uint8Array.of(0, 1));
        assert.equal(util.OS2IP(buf), 1);
    });

    it("input x=257, xLen=3", async () => {
        let buf = util.I2OSP(257, 3);
        assert.deepEqual(buf, Uint8Array.of(0, 1, 1));
        assert.equal(util.OS2IP(buf), 257);
    });

    it("input x=100000, xLen=2", async () => {
        assert.throws(() => {
            util.I2OSP(100000, 2);
        });
    });

    it("input [0,0,0,0,0]", async () => {
        assert.throws(() => {
            util.OS2IP(Uint8Array.of(0, 0, 0, 0, 0));
        });
    });
});

describe("strxor", () => {

    it("input str1=abc, str2=XYZ", async () => {
        let str1 = util.str2buf("abc");
        let str2 = util.str2buf("XYZ");
        let buf = util.strxor(str1, str2);
        assert.deepEqual(buf, util.str2buf("9;9"));
    });
});

describe("concat", () => {

    it("input a=ABC, b=DEF", async () => {
        let a = util.str2buf("ABC");
        let b = util.str2buf("DEF");
        let buf = util.concat(a, b);
        assert.deepEqual(buf, util.str2buf("ABCDEF"));
    });
});

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#appendix-K.2

describe("expand_message_xmd_sha512", () => {

    async function uniformBytesHex(s) {
        const msg = util.str2buf(s);
        const DST = util.str2buf("QUUX-V01-CS02-with-expander");
        let buf = await util.expand_message_xmd_sha512(msg, DST, 0x20);
        return util.buf2hex(buf);
    }

    it("input empty string", async () => {
        const r = await uniformBytesHex("");
        assert.equal(r, "2eaa1f7b5715f4736e6a5dbe288257abf1faa028680c1d938cd62ac699ead642");
    });

    it("input abc", async () => {
        const r = await uniformBytesHex("abc");
        assert.equal(r, "0eeda81f69376c80c0f8986496f22f21124cb3c562cf1dc608d2c13005553b0f");
    });

    it("input abcdef0123456789", async () => {
        const r = await uniformBytesHex("abcdef0123456789");
        assert.equal(r, "2e375fc05e05e80dbf3083796fde2911789d9e8847e1fcebf4ca4b36e239b338");
    });

    it("input q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", async () => {
        const r = await uniformBytesHex("q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq");
        assert.equal(r, "c37f9095fe7fe4f01c03c3540c1229e6ac8583b07510085920f62ec66acc0197");
    });

    it("input a512_aaa.......aaa.....aaa", async () => {
        const msg = "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        const r = await uniformBytesHex(msg);
        assert.equal(r, "af57a7f56e9ed2aa88c6eab45c8c6e7638ae02da7c92cc04f6648c874ebd560e");
    });
});
