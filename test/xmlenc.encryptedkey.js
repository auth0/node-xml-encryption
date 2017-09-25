var assert = require('assert'),
    fs = require('fs'),
    xmlenc = require('../lib');

var crypto = require('crypto');
var xmldom = require('xmldom');
var xpath = require('xpath');

describe('encrypt', function() {

  var algorithms = [{
    name: 'aes-256-cbc',
    encryptionOptions: {
      encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
      keyEncryptionAlgorighm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
    }
  }, {
    name: 'aes-128-cbc',
    encryptionOptions: {
      encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
      keyEncryptionAlgorighm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
    }
  }, {
    name: 'aes-256-gcm',
    encryptionOptions: {
      encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
      keyEncryptionAlgorighm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
    }
  }, {
    name: 'aes-128-gcm',
    encryptionOptions: {
      encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes128-gcm',
      keyEncryptionAlgorighm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
    }
  }, {
    name: 'des-ede3-cbc',
    encryptionOptions: {
      encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc',
      keyEncryptionAlgorighm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5'
    }
  }];

  algorithms.forEach(function (algorithm) {
    describe(algorithm.name, function () {
      it('should encrypt and decrypt xml', function (done) {
        _shouldEncryptAndDecrypt('content to encrypt', algorithm.encryptionOptions, done);
      });

      it('should encrypt and decrypt xml with utf8 chars', function (done) {
        _shouldEncryptAndDecrypt('Gnügge Gnügge Gnügge Gnügge Gnügge Gnügge Gnügge Gnügge Gnügge Gnügge', algorithm.encryptionOptions, done);
      });
    });
  });

  function _shouldEncryptAndDecrypt(content, options, done) {
    // cert created with:
    // openssl req -x509 -new -newkey rsa:2048 -nodes -subj '/CN=auth0.auth0.com/O=Auth0 LLC/C=US/ST=Washington/L=Redmond' -keyout auth0.key -out auth0.pem
    // pub key extracted from (only the RSA public key between BEGIN PUBLIC KEY and END PUBLIC KEY)
    // openssl x509 -in "test-auth0.pem" -pubkey

    options.rsa_pub = fs.readFileSync(__dirname + '/test-auth0_rsa.pub'),
    options.pem = fs.readFileSync(__dirname + '/test-auth0.pem'),
    options.key = fs.readFileSync(__dirname + '/test-auth0.key'),

    xmlenc.encrypt(content, options, function(err, result) {
      xmlenc.decrypt(result, { key: fs.readFileSync(__dirname + '/test-auth0.key')}, function (err, decrypted) {
        assert.equal(decrypted, content);
        done();
      });
    });
  }

  it('should encrypt and decrypt keyinfo', function (done) {
    var options = {
      rsa_pub: fs.readFileSync(__dirname + '/test-auth0_rsa.pub'),
      pem: fs.readFileSync(__dirname + '/test-auth0.pem'),
      keyEncryptionAlgorighm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
    };

    crypto.randomBytes(32, function(err, randomBytes) {
      if (err) return done(err);
      xmlenc.encryptKeyInfo(randomBytes, options, function(err, result) {
        if (err) return done(err);
        var decryptedRandomBytes = xmlenc.decryptKeyInfo(result, { key: fs.readFileSync(__dirname + '/test-auth0.key')});

        assert.equal(new Buffer(randomBytes).toString('base64'), new Buffer(decryptedRandomBytes).toString('base64'));
        done();
      });
    });
  });

  it('should decrypt xml with odd padding (aes256-cbc)', function (done) {
    var encryptedContent = fs.readFileSync(__dirname + '/test-cbc256-padding.xml').toString()
    xmlenc.decrypt(encryptedContent, { key: fs.readFileSync(__dirname + '/test-auth0.key')}, function(err, decrypted) {
      assert.ifError(err);
      assert.equal(decrypted, 'content');
      done();
    });
  });

  it('should catch error if padding length > 16', function (done) {
    var encryptedContent = fs.readFileSync(__dirname + '/test-padding-length.xml').toString();
    xmlenc.decrypt(encryptedContent, { key: fs.readFileSync(__dirname + '/test-auth0.key')}, function(err, decrypted) {
      assert(err);
      done();
    });
  });

});
