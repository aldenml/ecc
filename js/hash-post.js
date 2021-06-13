/**
 * @param {Uint8Array} input
 * @returns {Uint8Array}
 */
Module.ecc_hash_sha256 = (input) => {
    HEAPU8.set(input);

    let pIn = 0;
    let len = input.length;
    let pOut = pIn + len;

    _ecc_hash_sha256(pIn, len, pOut);

    return new Uint8Array(HEAPU8.subarray(pOut, pOut + 32));
}

/**
 * @param {Uint8Array} input
 * @returns {Uint8Array}
 */
Module.ecc_hash_sha512 = (input) => {
    HEAPU8.set(input);

    let pIn = 0;
    let len = input.length;
    let pOut = pIn + len;

    _ecc_hash_sha512(pIn, len, pOut);

    return new Uint8Array(HEAPU8.subarray(pOut, pOut + 64));
}
