#include "hash.h"
#include <sodium.h>

void ecc_hash_sha256(const unsigned char *in, int len, unsigned char *out) {
    crypto_hash_sha256(out, in, len);
}
