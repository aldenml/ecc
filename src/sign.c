#include "sign.h"
#include <sodium.h>

int ecc_sign_ed25519(BYTE *sm, int *smlen_p, const BYTE *m, int mlen, const BYTE *sk) {
    return crypto_sign_ed25519(sm, (unsigned long long *) smlen_p, m, mlen, sk);
}

int ecc_sign_ed25519_open(BYTE *m, int *mlen_p, const BYTE *sm, int smlen, const BYTE *pk) {
    return crypto_sign_ed25519_open(m, (unsigned long long *) mlen_p, sm, smlen, pk);
}

int ecc_sign_ed25519_detached(BYTE *sig, int *siglen_p, const BYTE *m, int mlen, const BYTE *sk) {
    return crypto_sign_ed25519_detached(sig, (unsigned long long *) siglen_p, m, mlen, sk);
}

int ecc_sign_ed25519_verify_detached(const BYTE *sig, const BYTE *m, int mlen, const BYTE *pk) {
    return crypto_sign_ed25519_verify_detached(sig, m, mlen, pk);
}

int ecc_sign_ed25519_keypair(BYTE *pk, BYTE *sk) {
    return crypto_sign_ed25519_keypair(pk, sk);
}

int ecc_sign_ed25519_seed_keypair(BYTE *pk, BYTE *sk, const BYTE *seed) {
    return crypto_sign_ed25519_seed_keypair(pk, sk, seed);
}

int ecc_sign_ed25519_pk_to_curve25519(BYTE *curve25519_pk, const BYTE *ed25519_pk) {
    return crypto_sign_ed25519_pk_to_curve25519(curve25519_pk, ed25519_pk);
}

int ecc_sign_ed25519_sk_to_curve25519(BYTE *curve25519_sk, const BYTE *ed25519_sk) {
    return crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, ed25519_sk);
}

int ecc_sign_ed25519_sk_to_seed(BYTE *seed, const BYTE *sk) {
    return crypto_sign_ed25519_sk_to_seed(seed, sk);
}

int ecc_sign_ed25519_sk_to_pk(BYTE *pk, const BYTE *sk) {
    return crypto_sign_ed25519_sk_to_pk(pk, sk);
}
