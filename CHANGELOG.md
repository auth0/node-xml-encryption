## [6.0.0](https://github.com/auth0/node-xml-encryption/compare/v5.0.0...v6.0.0) (2026-08-07)

### ⚠ BREAKING CHANGES

* **rsa-oaep-mgf1p now emits and expects MGF1-SHA1.** The `http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p` identifier fixes the mask generation function to MGF1-SHA1 per XML-Enc 1.1. Previously `keyEncryptionDigest: 'sha256'` or `'sha512'` also drove MGF1, producing MGF1-SHA256/SHA512 ciphertext that is not interoperable with spec-compliant peers (Java xmlsec, .NET `System.Security.Cryptography.Xml`). Such ciphertext will no longer decrypt with this version. Callers who genuinely need a non-SHA-1 MGF1 must switch to the `xmlenc11#rsa-oaep` identifier with the new `keyEncryptionMgf` option.

### Features

* **Support `http://www.w3.org/2009/xmlenc11#rsa-oaep`** — The new `keyEncryptionMgf` option selects the MGF1 digest (`sha1`, `sha224`, `sha256`, `sha384`, `sha512`, or the full `xmlenc11#mgf1*` URI; default `sha1`).
* **OAEP label support** — supply `keyEncryptionOaepParams` (a Buffer or base64 string) to set the OAEP label; it is emitted as an `<xenc:OAEPparams>` element and honoured on decrypt.
* Digest/MGF1 combinations Node's `crypto` cannot express (MGF1 digest ≠ message digest) are computed via an EME-OAEP shim over the raw RSA primitive.

## [5.0.0](https://github.com/auth0/node-xml-encryption/compare/v4.0.1...v5.0.0) (2026-07-02)

### ⚠ BREAKING CHANGES

* DigestMethod is not used when keyEncryptionAlgorithm is RSA 1.5 so has been removed from the encrypted payload
* keyEncryptionDigest values of sha256 or sha512 correctly use the `http://www.w3.org/2001/04/xmlenc` namespace when encrypting 

### Bug Fixes

* correct digest method and digest method algorithm id ([#136](https://github.com/auth0/node-xml-encryption/issues/136)) ([586edd3](https://github.com/auth0/node-xml-encryption/commit/586edd3e3fdc9783f108921036808a0ee54202d7))

## [4.0.1](https://github.com/auth0/node-xml-encryption/compare/v4.0.0...v4.0.1) (2026-06-25)

### Bug Fixes

* bump @xmldom/xmldom to 0.8.13 to address CVE-2026-34601 ([#128](https://github.com/auth0/node-xml-encryption/issues/128)) ([5980ce6](https://github.com/auth0/node-xml-encryption/commit/5980ce66534c545431f862b4daa3143cfc08e677))

## [4.0.0](https://github.com/auth0/node-xml-encryption/compare/v3.1.0...v4.0.0) (2026-03-31)

### ⚠ BREAKING CHANGES

- Moving CBC algorithms to insecure. ([#123](https://github.com/auth0/node-xml-encryption/pull/123)) ([b03887a](https://github.com/auth0/node-xml-encryption/commit/b03887afab7313ad9d8513012fd943f0da2780fb))
