/*
 * Copyright (c) 2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

package org.ssohub.crypto.ecc.opaque;

import static org.ssohub.crypto.ecc.libecc.ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE;

public final class ClientState {

    private final byte[] data;

    public ClientState() {
        this.data = new byte[ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE];
    }

    byte[] data() {
        return data;
    }
}
