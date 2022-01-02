/*
 * Copyright (c) 2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

package org.ssohub.crypto.ecc;

import static org.ssohub.crypto.ecc.libecc.*;

/**
 * @author aldenml
 */
public final class Oprf {

    private Oprf() {
    }

    public static byte[] oprf_ristretto255_sha512_Evaluate(
        byte[] skS,
        byte[] blindedElement,
        byte[] info
    ) {
        if (info == null)
            info = new byte[0];

        byte[] evaluatedElement = new byte[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
        ecc_oprf_ristretto255_sha512_Evaluate(
            evaluatedElement,
            skS,
            blindedElement,
            info, info.length
        );

        return evaluatedElement;
    }

    public static byte[] oprf_ristretto255_sha512_BlindWithScalar(
        byte[] input,
        byte[] blind
    ) {
        byte[] blindedElement = new byte[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
        ecc_oprf_ristretto255_sha512_BlindWithScalar(
            blindedElement,
            input, input.length,
            blind,
            ecc_oprf_ristretto255_sha512_MODE_BASE
        );

        return blindedElement;
    }

    public static byte[] oprf_ristretto255_sha512_Finalize(
        byte[] input,
        byte[] blind,
        byte[] evaluatedElement,
        byte[] info
    ) {
        if (info == null)
            info = new byte[0];

        byte[] output = new byte[ecc_oprf_ristretto255_sha512_Nh];
        ecc_oprf_ristretto255_sha512_Finalize(
            output,
            input, input.length,
            blind,
            evaluatedElement,
            info, info.length
        );

        return output;
    }
}
