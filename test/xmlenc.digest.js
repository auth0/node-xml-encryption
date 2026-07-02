var assert = require('assert');
var fs = require('fs');
var xmlenc = require('../lib');
var keyinfoTemplate = require('../lib/templates/keyinfo.tpl.xml');

var RSA_OAEP = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';
var RSA_1_5 = 'http://www.w3.org/2001/04/xmlenc#rsa-1_5';

describe('keyEncryptionDigest', function () {

  describe('keyinfo template DigestMethod', function () {
    function render(overrides) {
      return keyinfoTemplate(Object.assign({
        encryptionPublicCert: '<X509Data></X509Data>',
        encryptedKey: 'ZW5jcnlwdGVkS2V5',
        keyEncryptionMethod: RSA_OAEP,
        keyEncryptionDigest: 'sha1'
      }, overrides));
    }

    it('maps sha1 to the xmldsig sha1 URI', function () {
      var xml = render({ keyEncryptionDigest: 'sha1' });
      assert(xml.includes('<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />'));
    });

    it('maps sha256 to the xmlenc sha256 URI', function () {
      var xml = render({ keyEncryptionDigest: 'sha256' });
      assert(xml.includes('<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />'));
    });

    it('maps sha512 to the xmlenc sha512 URI', function () {
      var xml = render({ keyEncryptionDigest: 'sha512' });
      assert(xml.includes('<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512" />'));
    });

    it('passes through an unknown digest value unchanged', function () {
      var custom = 'http://example.org/custom#sha3-256';
      var xml = render({ keyEncryptionDigest: custom });
      assert(xml.includes('<DigestMethod Algorithm="' + custom + '" />'));
    });

    it('does NOT include a DigestMethod for RSA-1.5', function () {
      var xml = render({ keyEncryptionMethod: RSA_1_5, keyEncryptionDigest: 'sha256' });
      assert(!xml.includes('<DigestMethod'));
    });
  });

  describe('encrypt/decrypt round trip with digest', function () {
    function baseOptions() {
      return {
        rsa_pub: fs.readFileSync(__dirname + '/test-auth0_rsa.pub'),
        pem: fs.readFileSync(__dirname + '/test-auth0.pem'),
        key: fs.readFileSync(__dirname + '/test-auth0.key'),
        encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
        keyEncryptionAlgorithm: RSA_OAEP
      };
    }

    ['sha1', 'sha256', 'sha512'].forEach(function (digest) {
      it('round trips with ' + digest, function (done) {
        var options = baseOptions();
        options.keyEncryptionDigest = digest;
        var content = 'content encrypted with ' + digest;

        xmlenc.encrypt(content, options, function (err, result) {
          if (err) return done(err);
          xmlenc.decrypt(result, { key: fs.readFileSync(__dirname + '/test-auth0.key') }, function (err, decrypted) {
            if (err) return done(err);
            assert.equal(decrypted, content);
            done();
          });
        });
      });
    });

    it('emits the correct xmldsig URI in the produced XML for sha1', function (done) {
      var options = baseOptions();
      options.keyEncryptionDigest = 'sha1';
      xmlenc.encrypt('content', options, function (err, result) {
        if (err) return done(err);
        assert(result.includes('http://www.w3.org/2000/09/xmldsig#sha1'));
        done();
      });
    });

    it('emits the correct xmlenc URI in the produced XML for sha256', function (done) {
      var options = baseOptions();
      options.keyEncryptionDigest = 'sha256';
      xmlenc.encrypt('content', options, function (err, result) {
        if (err) return done(err);
        assert(result.includes('http://www.w3.org/2001/04/xmlenc#sha256'));
        assert(!result.includes('http://www.w3.org/2000/09/xmldsig#sha256'));
        done();
      });
    });

    it('emits the correct xmlenc URI in the produced XML for sha512', function (done) {
      var options = baseOptions();
      options.keyEncryptionDigest = 'sha512';
      xmlenc.encrypt('content', options, function (err, result) {
        if (err) return done(err);
        assert(result.includes('http://www.w3.org/2001/04/xmlenc#sha512'));
        assert(!result.includes('http://www.w3.org/2000/09/xmldsig#sha512'));
        done();
      });
    });
  });

  describe('decrypt backwards compatibility with old (wrong) xmldsig digest URIs', function () {
    function encryptWith(digest, cb) {
      var options = {
        rsa_pub: fs.readFileSync(__dirname + '/test-auth0_rsa.pub'),
        pem: fs.readFileSync(__dirname + '/test-auth0.pem'),
        key: fs.readFileSync(__dirname + '/test-auth0.key'),
        encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
        keyEncryptionAlgorithm: RSA_OAEP,
        keyEncryptionDigest: digest
      };
      xmlenc.encrypt('legacy digest content', options, cb);
    }

    it('decrypts a document using the legacy xmldsig#sha256 URI', function (done) {
      encryptWith('sha256', function (err, result) {
        if (err) return done(err);
        var legacy = result.replace(
          'http://www.w3.org/2001/04/xmlenc#sha256',
          'http://www.w3.org/2000/09/xmldsig#sha256'
        );
        xmlenc.decrypt(legacy, { key: fs.readFileSync(__dirname + '/test-auth0.key') }, function (err, decrypted) {
          if (err) return done(err);
          assert.equal(decrypted, 'legacy digest content');
          done();
        });
      });
    });

    it('decrypts a document using the legacy xmldsig#sha512 URI', function (done) {
      encryptWith('sha512', function (err, result) {
        if (err) return done(err);
        var legacy = result.replace(
          'http://www.w3.org/2001/04/xmlenc#sha512',
          'http://www.w3.org/2000/09/xmldsig#sha512'
        );
        xmlenc.decrypt(legacy, { key: fs.readFileSync(__dirname + '/test-auth0.key') }, function (err, decrypted) {
          if (err) return done(err);
          assert.equal(decrypted, 'legacy digest content');
          done();
        });
      });
    });
  });
});
