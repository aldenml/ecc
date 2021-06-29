/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "opaque.h"
#include "util.h"
#include "h2c.h"
#include "ristretto255.h"
#include "oprf.h"

void ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(
    byte_t *request,
    const byte_t *password, const int password_len,
    const byte_t *blind
) {
    // Steps:
    // 1. (blind, M) = Blind(password)
    // 2. Create RegistrationRequest request with M
    // 3. Output (request, blind)

    ecc_oprf_ristretto255_sha512_BlindWithScalar(request, password, password_len, blind);
}

void ecc_opaque_ristretto255_sha512_CreateRegistrationRequest(
    byte_t *request, byte_t *blind,
    const byte_t *password, const int password_len
) {
    ecc_ristretto255_scalar_random(blind);
    ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(request, password, password_len, blind);
}

void ecc_opaque_ristretto255_sha512_HashToScalar(byte_t *out, const byte_t *input, const int input_len) {
    byte_t dst[19] = "OPAQUE-HashToScalar";
    ecc_oprf_ristretto255_sha512_HashToGroupWithDST(out, input, input_len, dst, 19);
}

void ecc_opaque_ristretto255_sha512_DeriveAuthKeyPair(
    byte_t *private_key, byte_t *public_key,
    const byte_t *seed, const int seed_len
) {
    // Steps:
    // 1. private_key = HashToScalar(seed, dst="OPAQUE-HashToScalar")
    // 2. public_key = ScalarBaseMult(private_key)
    // 3. Output (private_key, public_key)

    ecc_opaque_ristretto255_sha512_HashToScalar(private_key, seed, seed_len);
    ecc_ristretto255_scalarmult_base(public_key, private_key);
}
