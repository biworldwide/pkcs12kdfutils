<?php

/**
 * http://opensource.org/licenses/MIT
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 BI Worldwide
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

namespace biworldwide\pkcs12kdfutils;

/**
 * Implementation of HashDigest for the 'SHA256' hash algorithm.
 *
 * @author Bibek Sahu <bibeksahu.tech@gmail.com>
 * @author Kevin Higgins <Kevin.Higgins@biworldwide.com>
 */
class SHA256Digest extends HashDigest
{
    const HASH_ALGORITHM = 'sha256';
    const HASH_SIZE_BYTES = 32;     // final hash size = 32 bytes = 256 bits
    const HASH_BYTE_LENGTH = 64;    // internal byte stream length = 64 bytes = 512 bits

    public function __construct()
    {
        parent::__construct(self::HASH_ALGORITHM, self::HASH_SIZE_BYTES, self::HASH_BYTE_LENGTH);
    }
}
