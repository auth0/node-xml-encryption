## [6.0.0](https://github.com/auth0/node-xml-encryption/compare/v5.0.0...v6.0.0) (2026-08-07)

### ⚠ BREAKING CHANGES

* the rsa-oaep-mgf1p identifier fixes MGF1 to SHA-1 per
XML-Enc 1.1 section 5.5.2, and DigestMethod selects only the OAEP message
digest. Ciphertext produced by this library with keyEncryptionDigest sha256
or sha512 (v3.1.0 through v5.0.0) used MGF1 matching the digest and no
longer decrypts; it was never interoperable with compliant peers.

* fix!: emit MGF1-SHA1 ciphertext for rsa-oaep-mgf1p
* encrypting with keyEncryptionDigest sha256 or sha512 under
rsa-oaep-mgf1p now wraps the key with MGF1-SHA1, as the identifier requires.
Peers that adapted to the previous non-compliant output must switch to the

### Features

* mask generation should use sha1 for rsa-oaep-mgf1p ([#140](https://github.com/auth0/node-xml-encryption/issues/140)) ([48f0059](https://github.com/auth0/node-xml-encryption/commit/48f0059c149e3b3518c40b7e3209908ae4181bc5)), closes [xmlenc11#rsa-oaep](https://github.com/auth0/xmlenc11/issues/rsa-oaep) [xmlenc11#rsa-oaep](https://github.com/auth0/xmlenc11/issues/rsa-oaep) [xmlenc11#rsa-oaep](https://github.com/auth0/xmlenc11/issues/rsa-oaep) [xmlenc11#mgf1sha1](https://github.com/auth0/xmlenc11/issues/mgf1sha1) [xmlenc#MGF1withSHA1](https://github.com/auth0/xmlenc/issues/MGF1withSHA1)

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
