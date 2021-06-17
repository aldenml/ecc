#ifndef ECC_HASH_H
#define ECC_HASH_H

#include "export.h"

ECC_EXPORT
void ecc_hash_sha256(BYTE *out, const BYTE *in, int len);

ECC_EXPORT
void ecc_hash_sha512(BYTE *out, const BYTE *in, int len);

#endif // ECC_HASH_H
