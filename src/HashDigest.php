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

use Exception;

/**
 * Class HashDigest
 *
 * Used to provide information to PKCS12 KDF routines on hashing sizes, and to actually run 'update()' and 'doFinal()'.
 *
 * Note: this is optimized for smaller data sets in PHP, as typically used in KDF routines.  If you want to work with larger data sets,
 * you should probably update this to use 'hash_update()' and 'hash_final()', and pack the data before sending it to those functions.
 *
 * @author Bibek Sahu <bibeksahu.tech@gmail.com>
 * @author Kevin Higgins <Kevin.Higgins@biworldwide.com>
 */
class HashDigest
{
    private $_hashAlgorithm;
    private $_hashSize;
    private $_hashByteLength;

    private $_data;

    /**
     * Constructor. Create a new HashDigest.
     * @param string $hashAlgo name of the hash algorithm, as used by PHP's "hash()" function.
     * @param integer $hashSize size of the hash output, in bytes. (Related to 'u' in RFC7292. $hashSize = u/8.)
     * @param integer $hashByteLength size of the internal hash stream, in bytes. (Related to 'v' in RFC7292. $hashByteLength = v/8.)
     */
    public function __construct($hashAlgo, $hashSize, $hashByteLength)
    {
        $this->_hashAlgorithm = $hashAlgo;
        $this->_hashSize = $hashSize;
        $this->_hashByteLength = $hashByteLength;

        $this->reset();
    }

    /**
     * Gets the size of the hash output, in bytes. (Related to 'u' in RFC7292. digestSize = u/8.)
     * @return integer the size of the hash output, in bytes.
     */
    public function getDigestSize()
    {
        return $this->_hashSize;
    }

    /**
     * Gets the size of the internal hash stream, in bytes. (Related to 'v' in RFC7292. byteLength = v/8.)
     * @return integer
     */
    public function getByteLength()
    {
        return $this->_hashByteLength;
    }

    /**
     * Resets this HashDigest to be used for new hash data.
     */
    public function reset()
    {
        $this->_data = [];
    }

    /**
     * Updates the hash stream with the provided values.
     * (Current implementation stores all values until 'doFinal()' is called.  Thus, this function updates the internal data.)
     * @param integer[] $values values to add to the hash stream.  Each element of $values should be a signed integer, representing a byte's value as a signed char.
     * @throws Exception if $values is not an array
     */
    public function update(&$values)
    {
        if (is_array($values)) {
            $this->_data = array_merge($this->_data, $values);
        } else {
            throw new Exception('SHA1Digest: update: Invalid values');
        }
    }

    /**
     * Finalizes the hash stream, and returns the resulting hash as an array of integers.
     * @param integer[] $outArray the resulting hash as an array of integers, where each element of $outArray represents the byte's value as a signed integer.
     */
    public function doFinal(&$outArray)
    {
        // pack up the data
        $packedData = PackUtils::bytesToString($this->_data);

        // run sha1() on the packed data
        // $shaData = sha1($packedData, true /* raw output */); // old versions of PHP
        $shaData = hash($this->_hashAlgorithm, $packedData, true /* raw output */);

        // unpack the resultant shaData
        $outArray = PackUtils::stringToBytes($shaData);

        // reset after running doFinal()
        $this->reset();
    }
}
