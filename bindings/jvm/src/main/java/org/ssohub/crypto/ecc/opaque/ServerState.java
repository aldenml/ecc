package org.ssohub.crypto.ecc.opaque;

import static org.ssohub.crypto.ecc.libecc.ecc_opaque_ristretto255_sha512_SERVERSTATESIZE;

public final class ServerState {

    private final byte[] data;

    public ServerState() {
        this.data = new byte[ecc_opaque_ristretto255_sha512_SERVERSTATESIZE];
    }

    byte[] data() {
        return data;
    }
}
