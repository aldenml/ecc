import libecc_module from "./libecc.js";
import assert from "assert";

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

    it("test a random invalid point", async () => {
        const libecc = await libecc_module();
        let p = new Uint8Array(32);
        libecc.ecc_ed25519_random(p);
        libecc.ecc_increment(p, p.length);
        let r = libecc.ecc_ed25519_is_valid_point(p);
        assert.ok(!r);
    });
});
