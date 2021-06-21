/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

import express from "express";
import bodyParser from "body-parser";
import * as oprf from "@aldenml/oprf";

const skSm = oprf.hex2buf("758cbac0e1eb4265d80f6e6489d9a74d788f7ddeda67d7fb3c08b08f44bda30a");

const app = express()
const port = 8000

app.use(express.static('public'));

app.post('/evaluate', bodyParser.text(), async (req, res) => {
    const blindedElement = req.body;
    console.log("blindedElement: " + blindedElement);
    const evaluationElement = await oprf.oprf_ristretto255_sha512_Evaluate(skSm, oprf.hex2buf(blindedElement));
    res.send(oprf.buf2hex(evaluationElement));
})

app.listen(port, () => {
    console.log(`App listening at http://localhost:${port}`)
})
