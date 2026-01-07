var escapehtml = require('escape-html');

const DIGEST_ALGORITHMS = {
    'sha1': 'http://www.w3.org/2000/09/xmldsig#sha1',
    'sha256': 'http://www.w3.org/2001/04/xmlenc#sha256',
    'sha512': 'http://www.w3.org/2001/04/xmlenc#sha512'
};

module.exports = ({ encryptionPublicCert, encryptedKey, keyEncryptionMethod, keyEncryptionDigest }) => {
    const digestUri = DIGEST_ALGORITHMS[keyEncryptionDigest] || keyEncryptionDigest;

    // RSA-OAEP requires it. RSA-1.5 must NOT have it.
    const isOAEP = keyEncryptionMethod && keyEncryptionMethod.includes('rsa-oaep');
    return `
<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
  <e:EncryptedKey xmlns:e="http://www.w3.org/2001/04/xmlenc#">
    <e:EncryptionMethod Algorithm="${escapehtml(keyEncryptionMethod)}">
      ${isOAEP ? `<DigestMethod Algorithm="${escapehtml(digestUri)}" />` : ''}
    </e:EncryptionMethod>
    <KeyInfo>
      ${encryptionPublicCert}
    </KeyInfo>
    <e:CipherData>
      <e:CipherValue>${escapehtml(encryptedKey)}</e:CipherValue>
    </e:CipherData>
  </e:EncryptedKey>
</KeyInfo>
`;
}