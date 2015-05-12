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
 * Utility functions to pack and unpack common data formats.
 * Simplifies use of PHP's "pack()" and "unpack()" functions.
 *
 * @author Bibek Sahu <bibeksahu.tech@gmail.com>
 * @author Kevin Higgins <Kevin.Higgins@biworldwide.com>
 */
class PackUtils
{
    /**
     * Pack an array to a string, using format $format
     * @param string $format the format string, per the PHP 'pack' function
     * @param integer[] $arr the array of values
     * @return string           the packed string
     */
    public static function packArrayToString($format, &$arr)
    {
        $str = call_user_func_array("pack", array_merge([$format], $arr));
        return $str;
    }

    /**
     * Unpack a string into an array of integers, representing the values
     * @param string $format the format string, per the PHP 'pack' function
     * @param string $str the source string
     * @return integer[]        an array, where each value corresponds to one element (byte, etc.) of the input string
     */
    public static function unpackStringToArray($format, $str)
    {
        return array_values(unpack($format, $str));
    }

    /**
     * Pack an array of byte-values into a string
     * @param integer[] $bytes
     * @return string
     */
    public static function bytesToString(&$bytes)
    {
        return self::packArrayToString("c*", $bytes);
    }

    /**
     * Unpack a string of bytes into an array, where each element of the array is the value of the corresponding byte in the string
     *
     * @param string $str
     * @return integer[]
     */
    public static function stringToBytes($str)
    {
        return self::unpackStringToArray('c*', $str);
    }
}