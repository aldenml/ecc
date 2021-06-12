import hash_module from "./hash.js";
import assert from "assert";
import {describe, it} from "mocha";

function str2buf(s) {
    const encoder = new TextEncoder();
    return encoder.encode(s);
}

function buf2hex(buffer) {
    return [...new Uint8Array(buffer)].map(x => x.toString(16).padStart(2, '0')).join('');
}

async function hash_ecc_hash_sha256(s) {
    const hash = await hash_module();
    return buf2hex(hash.ecc_hash_sha256(str2buf(s)));
}

// Test vectors
// https://www.di-mgt.com.au/sha_testvectors.html#FIPS-180

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
