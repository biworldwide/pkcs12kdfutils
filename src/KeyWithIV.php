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
 * Class to store information about Key and Initialization Vector (IV) for a cipher.
 *
 * @author Bibek Sahu <bibeksahu.tech@gmail.com>
 * @author Kevin Higgins <Kevin.Higgins@biworldwide.com>
 */
class KeyWithIV
{
    /**
     * A binary string representing the key
     * @var string
     */
    public $key = null;
    
    /**
     * An array representing the signed-integer values of the bytes in the key
     * @var integer[]
     */
    public $keyBytes = null;
    
    /**
     * A binary string representing the initialization vector (IV)
     * @var string
     */
    public $iv = null;
    
    /**
     * An array representing the signed-integer values of the bytes in the initialization vector (IV)
     * @var integer[]
     */
    public $ivBytes = null;
}
