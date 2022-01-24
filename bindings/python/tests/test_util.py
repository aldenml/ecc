#
# Copyright (c) 2022, Alden Torres
#
# Licensed under the terms of the MIT license.
# Copy of the license at https://opensource.org/licenses/MIT
#

import unittest
import src.libecc as libecc


class TestUtil(unittest.TestCase):

    def test_ecc_randombytes(self):
        buf = bytearray(10)
        libecc.ecc_randombytes(buf, len(buf))
        count = 0
        for b in buf:
            if b == 0:
                count = count + 1
        # what are the odds of having more than one 0 in a random of 10 elements
        self.assertTrue(count < 2)


if __name__ == '__main__':
    unittest.main()
