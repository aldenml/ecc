#ifndef ECC_HASH_H
#define ECC_HASH_H

#include "export.h"

ECC_EXPORT void ecc_hash_sha256(const unsigned char *in, int len, unsigned char *out);

#endif // ECC_HASH_H
