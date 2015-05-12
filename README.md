PKCS#12 KDF Utils
=================

The PKCS#12 KDF Utils provides routines to implement the PKCS#12 v1.0 Key Derivation Function (KDF)


Simple use for AES
------------------

To encrypt data using PKCS#12 KDF with AES (via OpenSSL), the simplest means is to use the wrapper methods in the "PKCS12AESUtils" class.

E.g.,

    $encryptedData = PKCS12AESUtils::encryptAES256PBEPKCS12( PKCS12AESUtils::HASH_SHA256, $sourceData, $password, $salt /* 16-byte salt */, 65000 /* iterationCount */ );


Manually generating a key and IV via PKCS#12 KDF
------------------------------------------------

To manually generate a cipher key and initialization vector (IV), use the methods in 

    $kdfGenerator = new PKCS12_KDF(new SHA256Digest());
    $keyWithIV = $kdfGenerator->generatePKCS12KeyAndIV($password, $salt, 65000 /* iterationCount */, 256 /* keySize in bits */, 128 /* ivSize in bits */);

