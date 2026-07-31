[![Build Status](https://travis-ci.org/auth0/node-xml-encryption.png)](https://travis-ci.org/auth0/node-xml-encryption)

W3C XML Encryption implementation for Node.js (http://www.w3.org/TR/xmlenc-core/)

Node 18+ does not support Triple DES algorithms due to https://github.com/nodejs/node/issues/52017

## Usage

    npm install xml-encryption

### encrypt

~~~js
var xmlenc = require('xml-encryption');

var options = {
  rsa_pub: fs.readFileSync(__dirname + '/your_rsa.pub'),
  pem: fs.readFileSync(__dirname + '/your_public_cert.pem'),
  encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
  keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
  keyEncryptionDigest: 'sha1',
  disallowEncryptionWithInsecureAlgorithm: true,
  warnInsecureAlgorithm: true
};

xmlenc.encrypt('content to encrypt', options, function(err, result) {
    console.log(result);
}
~~~

Result:
~~~xml
<xenc:EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
  <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes-256-cbc" />
    <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
      <e:EncryptedKey xmlns:e="http://www.w3.org/2001/04/xmlenc#">
        <e:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p">
          <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
        </e:EncryptionMethod>
        <KeyInfo>
          <X509Data><X509Certificate>MIIEDzCCAveg... base64 cert... q3uaLvlAUo=</X509Certificate></X509Data>
        </KeyInfo>
        <e:CipherData>
          <e:CipherValue>sGH0hhzkjmLWYYY0gyQMampDM... encrypted symmetric key ...gewHMbtZafk1MHh9A==</e:CipherValue>
        </e:CipherData>
      </e:EncryptedKey>
    </KeyInfo>
    <xenc:CipherData>
        <xenc:CipherValue>V3Vb1vDl055Lp92zvK..... encrypted content.... kNzP6xTu7/L9EMAeU</xenc:CipherValue>
    </xenc:CipherData>
</xenc:EncryptedData>
~~~

### decrypt

~~~js
var options = {
    key: fs.readFileSync(__dirname + '/your_private_key.key'),
    disallowDecryptionWithInsecureAlgorithm: true,
    warnInsecureAlgorithm: true
};

xmlenc.decrypt('<xenc:EncryptedData ..... </xenc:EncryptedData>', options, function(err, result) {
    console.log(result);
}

// result

decrypted content
~~~

## Supported algorithms

Currently the library supports:

* EncryptedKey to transport symmetric key using:
  * http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p
  * http://www.w3.org/2009/xmlenc11#rsa-oaep
  * http://www.w3.org/2001/04/xmlenc#rsa-1_5 (Insecure Algorithm)

* EncryptedData using:
  * http://www.w3.org/2001/04/xmlenc#aes128-cbc (Insecure Algorithm)
  * http://www.w3.org/2001/04/xmlenc#aes256-cbc (Insecure Algorithm)
  * http://www.w3.org/2009/xmlenc11#aes128-gcm
  * http://www.w3.org/2009/xmlenc11#aes256-gcm
  * http://www.w3.org/2001/04/xmlenc#tripledes-cbc (Insecure Algorithm)

Insecure Algorithms can be used via `disallowEncryptionWithInsecureAlgorithm`/`disallowDecryptionWithInsecureAlgorithm` flags when encrypting/decrypting by setting them to false. In version 4.0 onwards, these flags are true by default (forbidding insecure algorithms).

A warning will be piped to `stderr` using console.warn() by default when the aforementioned algorithms are used and above mentioned flags are false. This can be disabled via the `warnInsecureAlgorithm` flag.

We recommend usage of AES-256-GCM (Galois/Counter Mode) for the strongest security posture and to align with current industry best practices.

Note that `xml-encryption` versions prior to 4.0 supported AES-128-CBC and AES-256-CBC as secure algorithms. In version 4.0 onwards, these are treated as insecure because they use the Cipher Block Chaining (CBC) mode of encryption, which does not provide integrity guarantees. To continue using AES128-CBC and AES256-CBC, enable support for insecure algorithms via `disallowEncryptionWithInsecureAlgorithm/disallowDecryptionWithInsecureAlgorithm`.

### RSA-OAEP mask generation (MGF1)

`http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p` fixes the mask generation function to **MGF1 with SHA-1**, per [XML Encryption 1.1 §5.5.2][xmlenc-oaep]. `keyEncryptionDigest` selects only the OAEP message digest, so `keyEncryptionDigest: 'sha256'` means OAEP-SHA256 with MGF1-SHA1.

To use a different MGF1 digest, use the XML Encryption 1.1 identifier, which carries an explicit `<MGF>` element:

~~~js
var options = {
  keyEncryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
  keyEncryptionDigest: 'sha256',
  keyEncryptionMgf: 'sha256'   // sha1 | sha224 | sha256 | sha384 | sha512, default sha1
};
~~~

`keyEncryptionMgf` accepts either a short digest name (`sha1`, `sha224`, `sha256`, `sha384`, or `sha512`) or a full `http://www.w3.org/2009/xmlenc11#mgf1*` URI. It is rejected with `rsa-oaep-mgf1p`, which has no valid MGF other than SHA-1.

An optional OAEP label may be supplied as `keyEncryptionOaepParams` (a Buffer or a base64 string); it is emitted as `<OAEPparams>` and honoured on decrypt.

Note: for the digest/MGF1 combinations Node's `crypto` cannot express, the OAEP padding is computed in JavaScript over the raw RSA primitive. That code path cannot offer the constant-time guarantees of OpenSSL's C implementation. It is used only when the MGF1 digest differs from the message digest or a label is present; all other combinations go through `crypto.privateDecrypt` unchanged.

**Breaking change:** in versions 3.1.0 through 5.0.0, `rsa-oaep-mgf1p` with `keyEncryptionDigest: 'sha256'` or `'sha512'` produced ciphertext using MGF1-SHA256 or MGF1-SHA512, which was never compliant with the W3C specification. `rsa-oaep-mgf1p` now produces MGF1-SHA1 ciphertext regardless of `keyEncryptionDigest`. Documents encrypted with the earlier behaviour will not decrypt with the current version; they were never interoperable with Java xmlsec, .NET `System.Security.Cryptography.Xml`, or other spec-compliant peers. Callers who genuinely need MGF1-SHA256 or MGF1-SHA512 should use `http://www.w3.org/2009/xmlenc11#rsa-oaep` with the `keyEncryptionMgf` option.

[xmlenc-oaep]: https://www.w3.org/TR/xmlenc-core1/#sec-RSA-OAEP

### Allow listing specific algorithms when decrypting

If decrypting with `disallowEncryptionWithInsecureAlgorithm: true`, you may wish to only support a subset of insecure algorithms (for example, supporting AES-256-CBC only). This can be achieved by extracting the encryption algorithm using the following code and applying validation as required.

~~~js
const xmldom  = require('@xmldom/xmldom');
const xpath   = require('xpath');

const doc = new xmldom.DOMParser().parseFromString(xmlString);
const encryptionMethod = xpath.select("//*[local-name(.)='EncryptedData']/*[local-name(.)='EncryptionMethod']", doc)[0];
const encryptionAlgorithm = encryptionMethod.getAttribute('Algorithm');
~~~

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## Author

[Auth0](auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.

## Releases
Release notes may be found under github release page: https://github.com/auth0/node-xml-encryption/releases
