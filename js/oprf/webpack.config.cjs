/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

const path = require('path');

module.exports = env => {
    return {
        mode: "production",
        entry: "./index.js",
        output: {
            path: path.resolve(__dirname, "dist"),
            filename: env.mode === "prod" ? "oprf.min.js" : "oprf.dev.js",
            publicPath: "",
            library: "oprf",
        },
        resolve: {
            fallback: {
                "crypto": false,
            }
        },
        optimization: {
            minimize: env.mode === "prod",
            providedExports: false,
            usedExports: false,
            mangleExports: false,
        },
    };
}
