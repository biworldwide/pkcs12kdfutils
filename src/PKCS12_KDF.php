<?php

namespace biworldwide\pkcs12kdfutils;

    /**
     * This file (PKCS12_KDF.php) is a rewrite of org.bouncycastle.crypto.generators.PKCS12ParametersGenerator (PKCS12ParametersGenerator.java).
     *
     * The BouncyCastle license can be found at: https://www.bouncycastle.org/licence.html
     *
     * It is reproduced here, since it is signficantly relevant.
     *
     * -------------------------------------------------------------------------------------------------------------------------------
     *
     * Please note this should be read in the same way as the MIT license.
     * License
     *
     * Copyright (c) 2000 - 2015 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
     *
     * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation
     * files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy,
     * modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
     * Software is furnished to do so, subject to the following conditions:
     *
     * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
     *
     * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
     * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
     * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
     * IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
     */

    /**
     * With regards to the work done by BI Worldwide, code should be considered to be under the MIT License.
     *
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

/**
 * This file (PKCS12_KDF.php) is a PHP rewrite of org.bouncycastle.crypto.generators.PKCS12ParametersGenerator (PKCS12ParametersGenerator.java).
 *
 * The original Java code is often listed alongside the new PHP code, which will hopefully clear up any confusion, and assist
 * in debugging, should problems be found.  Dealing with raw bytes is kind of a headache in PHP, but other than that, this is
 * a fairly straightforward conversion, implementing the same algorithm.
 *
 * 'uRShift' is a function found on Stack Overflow, at http://stackoverflow.com/questions/14428193/php-unsigned-right-shift-malfunctioning
 * No copyright is listed.
 *
 * The function 'arraycopy' was added to mimic Java's arraycopy function.  It's not super efficient, but it gets the job done.
 * It operates like java.lang.System.arraycopy().
 *
 * @author Bibek Sahu <bibeksahu.tech@gmail.com>
 * @author Kevin Higgins <Kevin.Higgins@biworldwide.com>
 */
class PKCS12_KDF
{
    const KEY_MATERIAL = 1; // public static final int KEY_MATERIAL = 1;
    const IV_MATERIAL = 2; // public static final int IV_MATERIAL  = 2;
    const MAC_MATERIAL = 3; // public static final int MAC_MATERIAL = 3;

    private $passwordBytes; // array of int, where each value is >= 0 and <= 255
    private $saltBytes; // array of int, where each value is >= 0 and <= 255
    private $iterationCount; // int

    private $digest = null; // new SHA1Digest();

    private $u; // int, use 20 for sha1
    private $v; // int, use 64 for sha1

    /**
     * Create a new PKCS12_KDF key-derivation class
     * Note: This has only ever been tested with 'SHA1Digest'.  While other digest methods _may_ work, that is not known.
     * @param HashDigest $digest the digest to use for hashing data
     */
    public function __construct(HashDigest $digest)
    {
        $this->digest = $digest;
        $this->u = $digest->getDigestSize();
        $this->v = $digest->getByteLength();
    }

    /**
     * Verify that the condition is true, or throw an exception.
     * Does nothing on success.
     *
     * @param boolean $condition
     * @throws \Exception
     */
    private function assert($condition)
    {
        if ($condition !== true) {
            throw new \Exception("Assertion Failed");
        }
    }

    /**
     * Unsigned Right Shift
     * Equivalent to the java code: "a >>> b";
     *
     * Found at: http://stackoverflow.com/questions/14428193/php-unsigned-right-shift-malfunctioning
     *
     * @param integer $a
     * @param integer $b
     * @return integer
     * @see http://stackoverflow.com/questions/14428193/php-unsigned-right-shift-malfunctioning
     */
    private function uRShift($a, $b)
    {
        if ($b == 0) {
            return $a;
        }
        return ($a >> $b) & ~(1 << (8 * PHP_INT_SIZE - 1) >> ($b - 1));
    }

    // *** original Java code: ***
    // /**
    //  * initialise the PBE generator.
    //  *
    //  * @param password the password converted into bytes (see below).
    //  * @param salt the salt to be mixed with the password.
    //  * @param iterationCount the number of iterations the "mixing" function
    //  * is to be applied for.
    //  */
    // public void init(
    //     byte[]  password,
    //     byte[]  salt,
    //     int     iterationCount)
    // {
    //     this.password = password;
    //     this.salt = salt;
    //     this.iterationCount = iterationCount;
    // }

    /**
     * initialise the PBE generator.
     *
     * @param integer[] $passwordBytes the password converted into bytes (see below).
     * @param integer[] $saltBytes the salt to be mixed with the password.
     * @param integer $iterationCount the number of iterations the "mixing" function
     * is to be applied for.
     */
    public function init($passwordBytes, $saltBytes, $iterationCount)
    {
        $this->passwordBytes = $passwordBytes;
        $this->saltBytes = $saltBytes;
        $this->iterationCount = $iterationCount;
    }


    /**
     * add a + b + 1, returning the result in a. The a value is treated
     * as a BigInteger of length (b.length * 8) bits. The result is
     * modulo 2^b.length in case of overflow.
     *
     *   byte[]  a
     *   int     aOff
     *   byte[]  b
     */
    private function adjust(&$a, $aOff, &$b)
    {
        $b_length = count($b);
        $x = ($b[$b_length - 1] & 0xff) + ($a[$aOff + $b_length - 1] & 0xff) + 1; // int  x = (b[b.length - 1] & 0xff) + (a[aOff + b.length - 1] & 0xff) + 1;

        $a[$aOff + $b_length - 1] = $x; // a[aOff + b.length - 1] = (byte)x;
        $x = $this->urShift($x, 8); // x >>>= 8;

        for ($i = $b_length - 2; $i >= 0; $i--) // for (int i = b.length - 2; i >= 0; i--)
        {
            $x += ($b[$i] & 0xff) + ($a[$aOff + $i] & 0xff); // x += (b[i] & 0xff) + (a[aOff + i] & 0xff);
            $a[$aOff + $i] = $x; // a[aOff + i] = (byte)x;
            $x = $this->urShift($x, 8); // x >>>= 8;
        }
    }

    /**
     * Copies data from the specified $src array at position $srcPos, to the $dest array at position $destPos, and copying $length items.
     *
     * This mimics Java's java.lang.System.arraycopy() function.  It's not super efficient, but it gets the job done.
     */
    private function arraycopy(&$src, $srcPos, &$dest, $destPos, $length)
    {
        for ($i = 0; $i < $length; ++$i) {
            $dest[$destPos + $i] = $src[$srcPos + $i];
        }
    }

    // *** original Java code: ***
    // private byte[] generateDerivedKey(
    //    int idByte,
    //    int n)

    /**
     * generation of a derived key ala PKCS12 V1.0.
     */
    private function generateDerivedKey($idByte, $n)
    {
        $D = []; // byte[]  D = new byte[v];
        $dKey = []; // byte[]  dKey = new byte[n];

        $D_length = $this->v;
        $dKey_length = $n;

        for ($i = 0; $i != $D_length; $i++) // for (int i = 0; i != D.length; i++)
        {
            $D[$i] = $idByte; // D[i] = (byte)idByte;
        }

        $S = []; // byte[]  S;
        $S_length = 0;

        if (!empty($this->saltBytes)) // if ((salt != null) && (salt.length != 0))
        {
            // S = new byte[v * ((salt.length + v - 1) / v)];
            $S = [];
            $S_length = $this->v * (int) ((count($this->saltBytes) + $this->v - 1) / $this->v);

            for ($i = 0; $i != $S_length; $i++) // for (int i = 0; i != S.length; i++)
            {
                $S[$i] = $this->saltBytes[$i % count($this->saltBytes)]; // S[i] = salt[i % salt.length];
            }
        } else {
            // S = new byte[0];
            $S = [];
            $S_length = 0;
        }

        // byte[]  P;
        $P = [];
        $P_length = 0;

        if (!empty($this->passwordBytes)) // if ((password != null) && (password.length != 0))
        {
            // P = new byte[v * ((password.length + v - 1) / v)];
            $P = [];
            $P_length = $this->v * (int) ((count($this->passwordBytes) + $this->v - 1) / $this->v);

            for ($i = 0; $i != $P_length; $i++) // for (int i = 0; i != P.length; i++)
            {
                $P[$i] = $this->passwordBytes[$i % count($this->passwordBytes)]; // P[i] = password[i % password.length];
            }
        } else {
            // P = new byte[0];
            $P = [];
            $P_length = 0;
        }

        // byte[]  I = new byte[S.length + P.length];
        $I = [];
        $I_length = $S_length + $P_length;

        //System.arraycopy(S, 0, I, 0, S.length);
        //System.arraycopy(P, 0, I, S.length, P.length);
        $I = array_merge($S, $P);
        //             echo "I_length = (" . gettype($I_length) . ") $I_length, count(I) = (" . gettype(count($I)) . ") " . count($I) . "\n";
        $this->assert($I_length == count($I));

        // byte[]  B = new byte[v];
        $B = [];
        $B_length = $this->v;

        // int     c = (n + u - 1) / u;
        $c = (int) (($n + $this->u - 1) / $this->u);

        // byte[]  A = new byte[u];
        $A = [];
        $A_length = $this->u;

        for ($i = 1; $i <= $c; $i++) // for (int i = 1; i <= c; i++)
        {
            $this->digest->update($D, 0, $D_length); // digest.update(D, 0, D.length);
            $this->digest->update($I, 0, $I_length); // digest.update(I, 0, I.length);
            $this->digest->doFinal($A, 0); // digest.doFinal(A, 0);
            // A = SHA1(D + I);

            for ($j = 1; $j < $this->iterationCount; $j++) // for (int j = 1; j < iterationCount; j++)
            {
                $this->digest->update($A, 0, $A_length); // digest.update(A, 0, A.length);
                $this->digest->doFinal($A, 0); // digest.doFinal(A, 0);
                // A = SHA1(A)
            }

            for ($j = 0; $j != $B_length; $j++) // for (int j = 0; j != B.length; j++)
            {
                $B[$j] = $A[$j % $A_length]; // B[j] = A[j % A.length];
            }

            for ($j = 0; $j != $I_length / $this->v; $j++) // for (int j = 0; j != I.length / v; j++)
            {
                $this->adjust($I, $j * $this->v, $B); // adjust(I, j * v, B);
            }

            if ($i == $c) // if (i == c)
            {
                // System.arraycopy(A, 0, dKey, (i - 1) * u, dKey.length - ((i - 1) * u));
                $this->arraycopy($A, 0, $dKey, ($i - 1) * $this->u, $dKey_length - (($i - 1) * $this->u));
            } else {
                // System.arraycopy(A, 0, dKey, (i - 1) * u, A.length);
                $this->arraycopy($A, 0, $dKey, ($i - 1) * $this->u, $A_length);
            }
        }

        return $dKey; // return dKey;
    }

    // *** original Java code: ***
    // /**
    //  * Generate a key with initialisation vector parameter derived from
    //  * the password, salt, and iteration count we are currently initialised
    //  * with.
    //  *
    //  * @param keySize the size of the key we want (in bits)
    //  * @param ivSize the size of the iv we want (in bits)
    //  * @return a ParametersWithIV object.
    //  */
    // public CipherParameters generateDerivedParameters(
    //     int     keySize,
    //     int     ivSize)

    /**
     * Generate a key with initialisation vector parameter derived from
     * the password, salt, and iteration count we are currently initialised
     * with.
     *
     * @param int $keySize the size of the key we want (in bits)
     * @param int $ivSize the size of the iv we want (in bits)
     * @return KeyWithIV a \biworldwide\pkcs12kdfutils\KeyWithIV object
     */
    public function generateDerivedParameters($keySize, $ivSize)
    {
        $keySize = $keySize / 8; // keySize = keySize / 8;
        $ivSize = $ivSize / 8; // ivSize = ivSize / 8;

        $dKey = $this->generateDerivedKey(self::KEY_MATERIAL,
            $keySize); // byte[]  dKey = generateDerivedKey(KEY_MATERIAL, keySize);

        $iv = $this->generateDerivedKey(self::IV_MATERIAL,
            $ivSize); // byte[]  iv = generateDerivedKey(IV_MATERIAL, ivSize);

        // return new ParametersWithIV(new KeyParameter(dKey, 0, keySize), iv, 0, ivSize);

        $keyWithIV = new KeyWithIV();
        $keyWithIV->keyBytes = $dKey;
        $keyWithIV->key = PackUtils::bytesToString($dKey);
        $keyWithIV->ivBytes = $iv;
        $keyWithIV->iv = PackUtils::bytesToString($iv);

        return $keyWithIV;
    }

    // /**
    //  * converts a password to a byte array according to the scheme in
    //  * PKCS12 (unicode, big endian, 2 zero pad bytes at the end).
    //  *
    //  * @param password a character array representing the password.
    //  * @return a byte array representing the password.
    //  */
    // *** original Java code: ***
    // public static byte[] PKCS12PasswordToBytes(
    //     char[]  password)
    // {
    //     if (password != null && password.length > 0)
    //     {
    //         // +1 for extra 2 pad bytes.
    //         byte[]  bytes = new byte[(password.length + 1) * 2];

    //         for (int i = 0; i != password.length; i ++)
    //         {
    //         bytes[i * 2] = (byte)(password[i] >>> 8);
    //         bytes[i * 2 + 1] = (byte)password[i];
    //         }

    //         return bytes;
    //     }
    //     else
    //     {
    //         return new byte[0];
    //     }
    // }

    /**
     * converts a password to a byte array (integer array) according to the scheme in
     * PKCS12 (unicode, big endian, 2 zero pad bytes at the end).
     *
     * @param string $password
     * @return integer[]
     */
    public static function PKCS12PasswordToBytes($password)
    {
        // $password is type string (ordinary PHP-string, ASCII)
        $keyArray = [];

        $password_length = strlen($password);
        for ($i = 0; $i < $password_length; ++$i) {
            $keyArray[] = 0;
            $keyArray[] = ord($password[$i]);
        }

        // pad with null-byte
        $keyArray[] = 0;
        $keyArray[] = 0;

        return $keyArray;
    }

    /**
     * Generate a PKCS#12 Key and IV from the provided password and salt and iterationCount, with the given keySize and ivSize
     * @param string $password
     * @param string $salt
     * @param integer $iterationCount
     * @param integer $keySize
     * @param integer $ivSize
     * @return \StdClass a class containing 'keyBytes', 'key', 'ivBytes', and 'iv' fields
     * @throws \Exception if the salt is the wrong size
     */
    public function generatePKCS12KeyAndIV($password, $salt, $iterationCount, $keySize, $ivSize)
    {
        $passwordBytes = self::PKCS12PasswordToBytes($password);

        $saltSize = $ivSize / 8;
        if (strlen($salt) != $saltSize) {
            throw new \Exception("Incorrect salt size");
        }

        $saltBytes = array_values(unpack('c*', $salt));

        $this->init($passwordBytes, $saltBytes, $iterationCount);

        return $this->generateDerivedParameters($keySize, $ivSize);
    }
}
