var escapehtml = require('escape-html');

const DIGEST_ALGORITHMS = Object.assign(Object.create(null), {
    // SHA-2 was published after 2000/09/xmldsig was locked, so sha256/sha512 live under 2001/04/xmlenc.
    'sha1': 'http://www.w3.org/2000/09/xmldsig#sha1',
    'sha256': 'http://www.w3.org/2001/04/xmlenc#sha256',
    'sha512': 'http://www.w3.org/2001/04/xmlenc#sha512'
});

const MGF_ALGORITHMS = Object.assign(Object.create(null), {
    'sha1': 'http://www.w3.org/2009/xmlenc11#mgf1sha1',
    'sha224': 'http://www.w3.org/2009/xmlenc11#mgf1sha224',
    'sha256': 'http://www.w3.org/2009/xmlenc11#mgf1sha256',
    'sha384': 'http://www.w3.org/2009/xmlenc11#mgf1sha384',
    'sha512': 'http://www.w3.org/2009/xmlenc11#mgf1sha512'
});

module.exports = ({ encryptionPublicCert, encryptedKey, keyEncryptionMethod, keyEncryptionDigest, keyEncryptionMgf, keyEncryptionOaepParams }) => {
    const digestUri = DIGEST_ALGORITHMS[keyEncryptionDigest] || keyEncryptionDigest;

    // RSA-1.5 doesn't hash the key, so it has no digest or DigestMethod. RSA-OAEP does.
    const isOAEP = keyEncryptionMethod && keyEncryptionMethod.includes('rsa-oaep');
    // Only xmlenc11#rsa-oaep carries an MGF element. For rsa-oaep-mgf1p the MGF
    // is fixed to SHA-1 and the element MUST NOT be present (XML-Enc 1.1 5.5.2).
    const isOAEP11 = keyEncryptionMethod === 'http://www.w3.org/2009/xmlenc11#rsa-oaep';
    const mgfUri = MGF_ALGORITHMS[keyEncryptionMgf] || keyEncryptionMgf;
    return `
<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
  <e:EncryptedKey xmlns:e="http://www.w3.org/2001/04/xmlenc#">
    <e:EncryptionMethod Algorithm="${escapehtml(keyEncryptionMethod)}">
      ${isOAEP && keyEncryptionOaepParams ? `<OAEPparams>${escapehtml(keyEncryptionOaepParams)}</OAEPparams>` : ''}
      ${isOAEP11 && mgfUri ? `<MGF xmlns="http://www.w3.org/2009/xmlenc11#" Algorithm="${escapehtml(mgfUri)}" />` : ''}
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