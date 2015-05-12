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
 * Utility functions to generate AES keys using PKCS#12 KDF,
 * and encrypt/decrypt data using AES and PKCS#12-KDF.
 *
 * @author Bibek Sahu <bibeksahu.tech@gmail.com>
 * @author Kevin Higgins <Kevin.Higgins@biworldwide.com>
 */
class PKCS12AESUtils
{
    const HASH_SHA1 = 'sha1';
    const HASH_SHA256 = 'sha256';
    const HASH_SHA384 = 'sha384';
    const HASH_SHA512 = 'sha512';

    /**
     * Returns the digest class corresponding to the given hash algorithm name
     * @param string $hashAlgo name of the hash algorithm.  Currently supports "md2", "md5", "sha1", "sha256", "sha384", "sha512".
     * @return HashDigest an instance of HashDigest for the algorithm specified
     * @throws \Exception if hash algorithm not recognized
     */
    public static function getDigest($hashAlgo)
    {
        switch ($hashAlgo) {
            case 'md2':
                return new MD2Digest();
            case 'md5':
                return new MD5Digest();
            case 'sha1':
                return new SHA1Digest();
            case 'sha256':
                return new SHA256Digest();
            case 'sha384':
                return new SHA384Digest();
            case 'sha512':
                return new SHA512Digest();
        }

        // if we got here, it means the hash algorithm is not recognized by this class
        throw new \Exception('Digest algorithm name not recognized by PKCS12AESUtils::getDigest(): ' . $hashAlgo);
    }

    /**
     * Generate a PBE encryption key and IV for AES-128 using PKCS#12 KDF with the given hash algorithm ($hashAlgo)
     * @param string $hashAlgo the name of the hash algorithm
     * @param string $password
     * @param string $salt
     * @param integer $iterationCount
     * @return \StdClass a class containing 'keyBytes', 'key', 'ivBytes', and 'iv' fields
     */
    public static function generatePKCS12KeyAndIVForAES128($hashAlgo, $password, $salt, $iterationCount)
    {
        $kdfGenerator = new PKCS12_KDF(self::getDigest($hashAlgo));
        return $kdfGenerator->generatePKCS12KeyAndIV($password, $salt, $iterationCount, 128, 128);
    }

    /**
     * Generate a PBE encryption key and IV for AES-192 using PKCS#12 KDF with SHA1
     * @param string $hashAlgo the name of the hash algorithm
     * @param string $password
     * @param string $salt
     * @param integer $iterationCount
     * @return \StdClass a class containing 'keyBytes', 'key', 'ivBytes', and 'iv' fields
     */
    public static function generatePKCS12KeyAndIVForAES192($hashAlgo, $password, $salt, $iterationCount)
    {
        $kdfGenerator = new PKCS12_KDF(self::getDigest($hashAlgo));
        return $kdfGenerator->generatePKCS12KeyAndIV($password, $salt, $iterationCount, 192, 128);
    }

    /**
     * Generate a PBE encryption key and IV for AES-256 using PKCS#12 KDF with SHA1
     * @param string $hashAlgo the name of the hash algorithm
     * @param string $password
     * @param string $salt
     * @param integer $iterationCount
     * @return \StdClass a class containing 'keyBytes', 'key', 'ivBytes', and 'iv' fields
     */
    public static function generatePKCS12KeyAndIVForAES256($hashAlgo, $password, $salt, $iterationCount)
    {
        $kdfGenerator = new PKCS12_KDF(self::getDigest($hashAlgo));
        return $kdfGenerator->generatePKCS12KeyAndIV($password, $salt, $iterationCount, 256, 128);
    }


    /**
     * Encrypt a block of data using 256-bit AES, with password-based encryption via PKCS#12 KDF and the given hash algorithm
     *
     * @param string $data a block of (unencrypted) data, possibly binary
     * @param string $hashAlgo the name of the hash algorithm
     * @param string $password
     * @param string $salt
     * @param number $iterationCount
     * @return string       a block of encrypted data, possibly binary
     */
    public static function encryptAES256PBEPKCS12($hashAlgo, $data, $password, $salt, $iterationCount)
    {
        $derivedKeyInfo = self::generatePKCS12KeyAndIVForAES256($hashAlgo, $password, $salt, $iterationCount);

        $opensslKey = $derivedKeyInfo->key;
        $opensslIV = $derivedKeyInfo->iv;

        $opensslCipherMethod = 'AES-256-CBC';
        $opensslOptions = OPENSSL_RAW_DATA;

        $encryptedData = openssl_encrypt($data, $opensslCipherMethod, $opensslKey, $opensslOptions, $opensslIV);

        return $encryptedData;
    }

    /**
     * Decrypt a block of data using 256-bit AES, with password-based encryption via PKCS#12 KDF and the given hash algorithm
     *
     * @param string $data a block of (unencrypted) data, possibly binary
     * @param string $hashAlgo the name of the hash algorithm
     * @param string $password
     * @param string $salt
     * @param number $iterationCount
     * @return string       a block of encrypted data, possibly binary
     */
    public static function decryptAES256PBEPKCS12($hashAlgo, $data, $password, $salt, $iterationCount)
    {
        $derivedKeyInfo = self::generatePKCS12KeyAndIVForAES256($hashAlgo, $password, $salt, $iterationCount);

        $opensslKey = $derivedKeyInfo->key;
        $opensslIV = $derivedKeyInfo->iv;

        $opensslCipherMethod = 'AES-256-CBC';
        $opensslOptions = OPENSSL_RAW_DATA;

        $decryptedData = openssl_decrypt($data, $opensslCipherMethod, $opensslKey, $opensslOptions, $opensslIV);

        return $decryptedData;
    }
}
