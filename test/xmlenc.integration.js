var assert = require('assert'),
    fs = require('fs'),
    xmlenc = require('../lib');

var crypto = require('crypto');
var xmldom = require('@xmldom/xmldom');
var xpath = require('xpath');

describe('integration', function() {

  it('should decrypt assertion with aes128', function (done) {
    var result = fs.readFileSync(__dirname + '/assertion-sha1-128.xml').toString();

    xmlenc.decrypt(result, { key: fs.readFileSync(__dirname + '/test-cbc128.key'), disallowDecryptionWithInsecureAlgorithm: false }, function (err, decrypted) {
      // decrypted content should finish with <saml2:Assertion>
      assert.equal(/<\/saml2:Assertion>$/.test(decrypted), true);
      done();
    });
  });

  it('should decrypt Okta assertion', function (done) {
    var encryptedContent = fs.readFileSync(__dirname + '/test-okta-enc-response.xml').toString()
    xmlenc.decrypt(
      encryptedContent,
      {key: fs.readFileSync(__dirname + '/test-okta.pem'), disallowDecryptionWithInsecureAlgorithm: false},
      (err, res) => {
        assert.ifError(err);
  
        done();    
      }
    );
  });

  // passport-wsfed-saml2 passes only the EncryptedData element, while Okta
  // places the referenced EncryptedKey beside it under EncryptedAssertion.
  it('should decrypt Okta assertion when given only the EncryptedData element', function (done) {
    var doc = new xmldom.DOMParser().parseFromString(
      fs.readFileSync(__dirname + '/test-okta-enc-response.xml').toString()
    );
    var encryptedData = doc.getElementsByTagNameNS('http://www.w3.org/2001/04/xmlenc#', 'EncryptedData')[0]
      || doc.getElementsByTagName('EncryptedData')[0];
    assert.equal(encryptedData.parentNode.localName, 'EncryptedAssertion');

    xmlenc.decrypt(
      encryptedData,
      {key: fs.readFileSync(__dirname + '/test-okta.pem'), disallowDecryptionWithInsecureAlgorithm: false},
      (err, res) => {
        assert.ifError(err);
        assert(/Assertion/.test(res));
        done();
      }
    );
  });
});
