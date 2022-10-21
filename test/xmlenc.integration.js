var assert = require('assert'),
    fs = require('fs'),
    xmlenc = require('../lib');

var crypto = require('crypto');
var xmldom = require('@xmldom/xmldom');
var xpath = require('xpath');

describe('integration', function() {

  it('should decrypt assertion with aes128', function (done) {
    var result = fs.readFileSync(__dirname + '/assertion-sha1-128.xml').toString();

    xmlenc.decrypt(result, { key: fs.readFileSync(__dirname + '/test-cbc128.key')}, function (err, decrypted) {
      // decrypted content should finish with <saml2:Assertion>
      assert.equal(/<\/saml2:Assertion>$/.test(decrypted), true);
      done();
    });
  });

  it('should decrypt Okta assertion', function (done) {
    var encryptedContent = fs.readFileSync(__dirname + '/test-okta-enc-response.xml').toString()
    xmlenc.decrypt(
      encryptedContent,
      {key: fs.readFileSync(__dirname + '/test-okta.pem')},
      (err, res) => {
        assert.ifError(err);
  
        done();    
      }
    );
  });
});
