/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

package org.ssohub.crypto.ecc;

/**
 * JNI java interface for libecc-jvm.
 *
 * @author aldenml
 */
public final class libecc {

    static {
        try {
            String path = System.getProperty("libecc.jni.path", "");
            if ("".equals(path)) {
                String libname = "ecc-jvm";
                String os = System.getProperty("os.name");
                if (os != null && os.toLowerCase(java.util.Locale.US).contains("windows"))
                    libname = "lib" + libname;

                System.loadLibrary(libname);
            } else {
                System.load(path);
            }
        } catch (LinkageError e) {
            throw new LinkageError(
                "Look for your architecture binary instructions at: https://github.com/aldenml/ecc", e);
        }
    }

    private libecc() {
    }

    // util

    public static void ecc_memzero(byte[] buf, int len) {
        for (int i = 0; i < len; i++) {
            buf[i] = 0;
        }
    }

    public static native void ecc_randombytes(byte[] buf, int len);
}
