var path = require('path'),
    fs = require('fs');

var templates = {
  'encrypted-key' (data) {
     return `<xenc:EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
      <xenc:EncryptionMethod Algorithm="${data.contentEncryptionMethod}" />
        ${data.keyInfo}
      <xenc:CipherData>
        <xenc:CipherValue>${data.encryptedContent}</xenc:CipherValue>
      </xenc:CipherData>
      </xenc:EncryptedData>`
  },
  'keyinfo' (data) {
    return `<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
      <e:EncryptedKey xmlns:e="http://www.w3.org/2001/04/xmlenc#">
        <e:EncryptionMethod Algorithm="${data.keyEncryptionMethod}">
          <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
        </e:EncryptionMethod>
        <KeyInfo>
          ${data.encryptionPublicCert}
        </KeyInfo>
        <e:CipherData>
          <e:CipherValue>${data.encryptedKey}</e:CipherValue>
        </e:CipherData>
      </e:EncryptedKey>
    </KeyInfo>
    `
  }
};

function renderTemplate (file, data) {
  return templates[file](data);
}

function pemToCert(pem) {
  var cert = /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g.exec(pem);
  if (cert.length > 0) {
    return cert[1].replace(/[\n|\r\n]/g, '');
  }

  return null;
};


module.exports = {
  renderTemplate: renderTemplate,
  pemToCert: pemToCert
};