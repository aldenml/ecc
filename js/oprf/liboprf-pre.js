function randomValueSetup() {
    if (Module.getRandomValue === undefined) {
        try {
            var window_ = 'object' === typeof window ? window : self;
            var crypto_ = typeof window_.crypto !== 'undefined' ? window_.crypto : window_.msCrypto;
            var randomValuesStandard = function () {
                var buf = new Uint32Array(1);
                crypto_.getRandomValues(buf);
                return buf[0] >>> 0;
            };
            randomValuesStandard();
            Module.getRandomValue = randomValuesStandard;
        } catch (e) {
            try {
                import("crypto").then((crypto) => {
                    var randomValueNodeJS = function () {
                        var buf = crypto['randomBytes'](4);
                        return (buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3]) >>> 0;
                    };
                    randomValueNodeJS();
                    Module.getRandomValue = randomValueNodeJS;
                });
            } catch (e) {
                throw 'No secure random number generator found';
            }
        }
    }
}

randomValueSetup();
