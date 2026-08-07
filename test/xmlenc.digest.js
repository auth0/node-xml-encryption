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

describe('DigestMethod resolution with RetrievalMethod', function () {
  var xpath = require('xpath');
  var xmldom = require('@xmldom/xmldom');

  it('finds the DigestMethod when EncryptedKey is outside KeyInfo', function () {
    var doc = new xmldom.DOMParser().parseFromString(
      fs.readFileSync(__dirname + '/test-okta-enc-response.xml', 'utf8')
    );
    // The pre-fix XPath, anchored under KeyInfo/EncryptedKey, finds nothing here.
    var anchored = xpath.select(
      "//*[local-name(.)='KeyInfo']/*[local-name(.)='EncryptedKey']/*[local-name(.)='EncryptionMethod']/*[local-name(.)='DigestMethod']",
      doc
    );
    assert.equal(anchored.length, 0, 'fixture must exercise the RetrievalMethod shape');

    // Resolving relative to the EncryptedKey's own EncryptionMethod does find it.
    var relative = xpath.select(
      "//*[local-name(.)='EncryptedKey']/*[local-name(.)='EncryptionMethod']/*[local-name(.)='DigestMethod']",
      doc
    );
    assert.equal(relative.length, 1);
    assert.equal(relative[0].getAttribute('Algorithm'), 'http://www.w3.org/2000/09/xmldsig#sha1');
  });

  it('decrypts a RetrievalMethod document whose DigestMethod is sha256', function (done) {
    // Build the RetrievalMethod shape with a sha256 digest, which the anchored
    // XPath would misread as sha1.
    var options = {
      rsa_pub: fs.readFileSync(__dirname + '/test-auth0_rsa.pub'),
      pem: fs.readFileSync(__dirname + '/test-auth0.pem'),
      encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
      keyEncryptionAlgorithm: RSA_OAEP,
      keyEncryptionDigest: 'sha256'
    };
    xmlenc.encrypt('retrieval method content', options, function (err, result) {
      if (err) return done(err);
      // Move EncryptedKey out of KeyInfo and point at it with a RetrievalMethod.
      var m = /<e:EncryptedKey[\s\S]*<\/e:EncryptedKey>/.exec(result);
      assert(m, 'expected an EncryptedKey element');
      var encryptedKey = m[0].replace('<e:EncryptedKey', '<e:EncryptedKey Id="ek1"');
      var rewritten = result
        .replace(m[0], '<RetrievalMethod URI="#ek1" />')
        .replace('</xenc:EncryptedData>', encryptedKey + '</xenc:EncryptedData>');

      xmlenc.decrypt(rewritten, { key: fs.readFileSync(__dirname + '/test-auth0.key') }, function (err2, decrypted) {
        if (err2) return done(err2);
        assert.equal(decrypted, 'retrieval method content');
        done();
      });
    });
  });
});

describe('rsa-oaep-mgf1p pins MGF1 to sha1', function () {
  var crypto = require('crypto');
  var oaep = require('../lib/oaep');

  // Build a KeyInfo whose EncryptedKey was wrapped with OAEP(sha256)/MGF1(sha1),
  // i.e. what a spec-compliant IdP such as ADFS or Okta actually sends.
  function specCompliantKeyInfo(symmetricKey, digest) {
    var pub = fs.readFileSync(__dirname + '/test-auth0_rsa.pub');
    var wrapped = oaep.publicEncryptOaep(pub, symmetricKey, { oaepHash: digest, mgf1Hash: 'sha1' });
    return '<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">' +
      '<e:EncryptedKey xmlns:e="http://www.w3.org/2001/04/xmlenc#">' +
      '<e:EncryptionMethod Algorithm="' + RSA_OAEP + '">' +
      '<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#' + digest + '" />' +
      '</e:EncryptionMethod>' +
      '<e:CipherData><e:CipherValue>' + wrapped.toString('base64') + '</e:CipherValue></e:CipherData>' +
      '</e:EncryptedKey></KeyInfo>';
  }

  ['sha256', 'sha512'].forEach(function (digest) {
    it('decrypts a spec-correct MGF1-sha1 key with DigestMethod ' + digest, function () {
      var symmetricKey = crypto.randomBytes(32);
      var recovered = xmlenc.decryptKeyInfo(specCompliantKeyInfo(symmetricKey, digest), {
        key: fs.readFileSync(__dirname + '/test-auth0.key')
      });
      assert.equal(Buffer.compare(Buffer.from(recovered), symmetricKey), 0);
    });
  });

  it('rejects a key wrapped with the non-spec MGF1=sha256', function () {
    var pub = fs.readFileSync(__dirname + '/test-auth0_rsa.pub');
    var wrapped = oaep.publicEncryptOaep(pub, crypto.randomBytes(32), { oaepHash: 'sha256', mgf1Hash: 'sha256' });
    var keyInfo = '<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">' +
      '<e:EncryptedKey xmlns:e="http://www.w3.org/2001/04/xmlenc#">' +
      '<e:EncryptionMethod Algorithm="' + RSA_OAEP + '">' +
      '<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />' +
      '</e:EncryptionMethod>' +
      '<e:CipherData><e:CipherValue>' + wrapped.toString('base64') + '</e:CipherValue></e:CipherData>' +
      '</e:EncryptedKey></KeyInfo>';
    assert.throws(function () {
      xmlenc.decryptKeyInfo(keyInfo, { key: fs.readFileSync(__dirname + '/test-auth0.key') });
    }, /oaep decoding error/);
  });

  it('decrypts the external OpenSSL vector through the public API', function () {
    // VECTOR from test/oaep.js (originally from repro-oaep-mgf1.cjs): OpenSSL OAEP(sha256)/MGF1(sha1)
    var VECTOR_KEY = Buffer.from(
      'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2UUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktjd2dnU2pBZ0VBQW9JQkFRQzA5QmY1NTRXR0VxRXYKMmZyUWxOUG9ycWRMbld5RVAyTGlybGwvekZuUHFnK0c5RkdxYnNNb3o3UG1CUDRpZlRhVFRtSkViaUx1ajkyWQpQM3FieU9JUmN6MkFZQXJkZlE3M0RiSXhYaUZsazNObjlvVnRISVJUcHVvZkwzc2FkVlozMGg5c3JVeTZ4N0Z1ClZvL0ErNDJlSEVRNEdhaGJOSjJsMlh2QU5ydGQwUG5jNlc2MS9pVTdQK3Z4WDJyM0Fqb2VLMjNTWVRxbTkxRTkKMlN0WmVKQjJuSm4rSGxaamV6WTVUblhCZy9HRmFCZGNvR1JMb1diYzFsV2Q0SHNYa1BuVExyTW5UL0xiV1pQZQo4QVpyU253R1Fpa3dud245ZjF3K01ZQ1h6QU0yNWE4STkrZXRacEl0cFN5VUVtWE9yMnEzRkVkMG5RUUVzMHNFCmkrbENlaW5oQWdNQkFBRUNnZ0VBRUpDdDV6YytIblZ6SXczSjY3Rk1LdWRlTWtwaGhrUEZPaW9xMEV1MVJ4RHkKNWZCVXo0emZPY3UxMU05Tk1ud1M5RzQvQ2JPcFoveHNsVVR1WlBlQlZvYWRzVFJabWtnYUNCek5YTDZZd1JNOApBOTdwL1FDWXpvMmZyaVlyRjFONWpIT0VZKzhEY0svYU90Y2F4dGhnY1FKMmJrcFBBclp3M2g5b09FTHFhUjZTClJyNDgxSUZtS0JNdmhyVUQxVFU0MG5jWG43MTdvazlxalR4bFNuOElONElxSmVMTDFPTkFTMDlNSkhISTZPdG8KbHRZUjNWc1RFdE9YTGNsQ2ZubU5ZT2xpeVgrL1VoMTZBak0rSlJmOFRNL2lDYjNkUGFxMyt4UUFCL1oxRnZPZAo0UEFpa01LNVFTc09jdHhxYThwbm10MUlLK1N4MEZ0aUIweThzbWdYM3dLQmdRRHIyNmxLMlIwbmRpWVZDK3hLCjB2SmxYZ0FZeG9TU1IxOS9EdEFQbDdNMkFVVFRzblVFNmlpSCtDbU1ZK1k5Qm0wblkrNGsveThNUG9sdHZ5OUsKQ1ZVT21Ka0hFY3IvZmo3WHl2OEdkTTJSeXVQOHFhRVZxUlh5WU9PMzM5OUt0NzBFb3FFWVJsS0MxQllXcTVWcQovRExURXphSEowSHFXSk85QjB5eW00cDJId0tCZ1FERWFCdEZGN0NqbG1lMVVjUXRDZ0pqZnZPVWF6UTQ3WGdxClpkNTZ6emcyWm5vejZjYzkvTE40WnV5OC8rcFRYcS9GL3E5RjZtb1pyYktHVDBlNFg4dlVtQVZxd3NmQ01TOGcKTWk4Ui8zeGRZdG54Ly9IbW5DUmpYYTJTOUoraWU1Wks3RHpZWGl0Vi9yamEwRHhvWG9RMm82TG9URXQ1WVNTdQpFY2dEclNkZi93S0JnQXZ5dk1qRjV1d3cyQTBJNVplRXlETEthRWJaQjY1QlgxMFlhd0hmTlh6dTQ0VzE3S2VyCkZSS09SOHlNNHdVRVpsTXdoTWZyQlg4aFMrVDdZbkhsdHlGZUthSnFERmFWRnFubjVyTjFCMVR6YWtsS2JwYWkKVWpKTkpqd1NZMFZ0dVcyYXIzNkRVWHEvTTc5Q1FmZUJmekdpTDRqNVBDV2JCeUQwVmJaV210VVJBb0dBY3ZncAo5bUR1c21QSm8zY1FxZml3KzBNR0hMeEFYbzZMaCs0SHRNWDJOc24wQU1sNUt3endsYXRTS3pSM0c0UlN5a2pTCm1zK2tlaEdXYms2Y1FnNDVoK0hSVWZSZzhJalArRDNJRmZZQys3dHdydHRPNDlwRTVyR2dlR1NmeVlJa3NRam0KZVJWdXNyRWZ6bDZVN2RkZDk0b0VRNHpkcFZpN0d2WW5xaGRDOUVzQ2dZRUFwSkJ1SEpFZXYwd1lxUStnNERzVwpxZTVQYWJOY1dVaDJrNUswMGwza0lmMlpweVdWRWs5bnhRVzJIOFVmNHNVc0d0VTBvMmUycEtUanJ1WDRWcVR5CitoeWxrOXZEam1MU29CenFEREU4bFdOK1llU3hBYzJ0WnE2TnpmT0FPZGdHOVN1ODI0MDlEcUtuR1RlQzlKKzAKWHJ6Z21WOGp5K013cU9kQXJ2QXJ0MXM9Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K',
      'base64'
    ).toString('utf8');
    var VECTOR_CT = Buffer.from(
      'fcAWGHe0HIxC3LcLBwwrkts3005XTSznQZTZZU6EiLOSh/fAfPoe0vF60RcK0IYGW1oDUfuwCl3W+C3HOPTRvFGHiI6AfKCKkj8pTna6WuAZP5x4lBdSKxkIoECgBp+GYko2TMlRn6aW0mOhMCw60P1lT5x93blbbYf4nh0reOtODA8VQBCHnS0wu+qFqIzG/x2UgIbrasnlHo45UlbxdfpOYR08ckKZZrltMZrLcoQnTgrwevwafOg9OvfpY9Kw5Aml+aBhdsabr2aQC5quE6nho0ar/QobPmG5+WzEB5eHn59fTQExDdV2KDcyi7E8xACOjkFFWr+VZmf6t1l59Q==',
      'base64'
    );
    // Wrap it with mgf1p + sha256 DigestMethod, which the library should decrypt with MGF1-sha1.
    var keyInfo = '<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">' +
      '<e:EncryptedKey xmlns:e="http://www.w3.org/2001/04/xmlenc#">' +
      '<e:EncryptionMethod Algorithm="' + RSA_OAEP + '">' +
      '<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />' +
      '</e:EncryptionMethod>' +
      '<e:CipherData><e:CipherValue>' + VECTOR_CT.toString('base64') + '</e:CipherValue></e:CipherData>' +
      '</e:EncryptedKey></KeyInfo>';
    var recovered = xmlenc.decryptKeyInfo(keyInfo, { key: VECTOR_KEY });
    assert.equal(recovered.toString('utf8'), 'AES-128-key-1234');
  });
});

describe('rsa-oaep-mgf1p emits MGF1-sha1 ciphertext', function () {
  var oaep = require('../lib/oaep');
  var xpath = require('xpath');
  var xmldom = require('@xmldom/xmldom');

  ['sha256', 'sha512'].forEach(function (digest) {
    it('wraps the key with MGF1-sha1 when keyEncryptionDigest is ' + digest, function (done) {
      var options = {
        rsa_pub: fs.readFileSync(__dirname + '/test-auth0_rsa.pub'),
        pem: fs.readFileSync(__dirname + '/test-auth0.pem'),
        encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
        keyEncryptionAlgorithm: RSA_OAEP,
        keyEncryptionDigest: digest
      };
      xmlenc.encrypt('mgf1 sha1 content', options, function (err, result) {
        if (err) return done(err);
        var doc = new xmldom.DOMParser().parseFromString(result);
        var cipherValue = xpath.select("//*[local-name(.)='EncryptedKey']/*[local-name(.)='CipherData']/*[local-name(.)='CipherValue']", doc)[0];
        var wrapped = Buffer.from(cipherValue.textContent, 'base64');

        // Unwrap with MGF1-sha1: succeeds only if encrypt used the spec MGF.
        var withSha1 = oaep.privateDecryptOaep(fs.readFileSync(__dirname + '/test-auth0.key'), wrapped, { oaepHash: digest, mgf1Hash: 'sha1' });
        assert.equal(withSha1.length, 32);

        // And the old non-spec MGF1=digest must no longer parse.
        assert.throws(function () {
          oaep.privateDecryptOaep(fs.readFileSync(__dirname + '/test-auth0.key'), wrapped, { oaepHash: digest, mgf1Hash: digest });
        }, /oaep decoding error/);
        done();
      });
    });
  });

  it('never emits an MGF element for mgf1p', function (done) {
    var options = {
      rsa_pub: fs.readFileSync(__dirname + '/test-auth0_rsa.pub'),
      pem: fs.readFileSync(__dirname + '/test-auth0.pem'),
      encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
      keyEncryptionAlgorithm: RSA_OAEP,
      keyEncryptionDigest: 'sha256'
    };
    xmlenc.encrypt('x', options, function (err, result) {
      if (err) return done(err);
      var doc = new xmldom.DOMParser().parseFromString(result);
      var mgf = xpath.select("//*[local-name(.)='EncryptedKey']/*[local-name(.)='EncryptionMethod']/*[local-name(.)='MGF']", doc);
      assert.equal(mgf.length, 0, 'MGF element must not be present with mgf1p');
      done();
    });
  });

  it('rejects MGF element when present with mgf1p', function () {
    var oaep = require('../lib/oaep');
    var pub = fs.readFileSync(__dirname + '/test-auth0_rsa.pub');
    var wrapped = oaep.publicEncryptOaep(pub, Buffer.alloc(32), { oaepHash: 'sha256', mgf1Hash: 'sha1' });
    var keyInfo = '<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">' +
      '<e:EncryptedKey xmlns:e="http://www.w3.org/2001/04/xmlenc#">' +
      '<e:EncryptionMethod Algorithm="' + RSA_OAEP + '">' +
      '<MGF xmlns="http://www.w3.org/2009/xmlenc11#" Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha256" />' +
      '<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />' +
      '</e:EncryptionMethod>' +
      '<e:CipherData><e:CipherValue>' + wrapped.toString('base64') + '</e:CipherValue></e:CipherData>' +
      '</e:EncryptedKey></KeyInfo>';
    assert.throws(function () {
      xmlenc.decryptKeyInfo(keyInfo, { key: fs.readFileSync(__dirname + '/test-auth0.key') });
    }, /MGF element must not be present/);
  });
});

describe('xmlenc11#rsa-oaep with explicit MGF', function () {
  var RSA_OAEP_11 = 'http://www.w3.org/2009/xmlenc11#rsa-oaep';
  var oaep = require('../lib/oaep');

  it('round trips sha256 digest with an explicit mgf1sha256', function (done) {
    var options = {
      rsa_pub: fs.readFileSync(__dirname + '/test-auth0_rsa.pub'),
      pem: fs.readFileSync(__dirname + '/test-auth0.pem'),
      encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
      keyEncryptionAlgorithm: RSA_OAEP_11,
      keyEncryptionDigest: 'sha256',
      keyEncryptionMgf: 'sha256'
    };
    xmlenc.encrypt('xmlenc11 content', options, function (err, result) {
      if (err) return done(err);
      assert(result.includes('http://www.w3.org/2009/xmlenc11#mgf1sha256'), 'expected MGF element');
      xmlenc.decrypt(result, { key: fs.readFileSync(__dirname + '/test-auth0.key') }, function (err2, decrypted) {
        if (err2) return done(err2);
        assert.equal(decrypted, 'xmlenc11 content');
        done();
      });
    });
  });

  it('round trips sha256 digest with mgf1sha1 (the default)', function (done) {
    var options = {
      rsa_pub: fs.readFileSync(__dirname + '/test-auth0_rsa.pub'),
      pem: fs.readFileSync(__dirname + '/test-auth0.pem'),
      encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
      keyEncryptionAlgorithm: RSA_OAEP_11,
      keyEncryptionDigest: 'sha256'
    };
    xmlenc.encrypt('default mgf', options, function (err, result) {
      if (err) return done(err);
      assert(result.includes('http://www.w3.org/2009/xmlenc11#mgf1sha1'));
      xmlenc.decrypt(result, { key: fs.readFileSync(__dirname + '/test-auth0.key') }, function (err2, decrypted) {
        if (err2) return done(err2);
        assert.equal(decrypted, 'default mgf');
        done();
      });
    });
  });

  it('rejects an unknown MGF URI rather than defaulting to sha1', function () {
    var pub = fs.readFileSync(__dirname + '/test-auth0_rsa.pub');
    var wrapped = oaep.publicEncryptOaep(pub, Buffer.alloc(32), { oaepHash: 'sha256', mgf1Hash: 'sha1' });
    var keyInfo = '<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">' +
      '<e:EncryptedKey xmlns:e="http://www.w3.org/2001/04/xmlenc#">' +
      '<e:EncryptionMethod Algorithm="' + RSA_OAEP_11 + '">' +
      '<MGF Algorithm="http://example.org/mgf1sha3" />' +
      '<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />' +
      '</e:EncryptionMethod>' +
      '<e:CipherData><e:CipherValue>' + wrapped.toString('base64') + '</e:CipherValue></e:CipherData>' +
      '</e:EncryptedKey></KeyInfo>';
    assert.throws(function () {
      xmlenc.decryptKeyInfo(keyInfo, { key: fs.readFileSync(__dirname + '/test-auth0.key') });
    }, /mask generation function/);
  });

  it('accepts the MGF1withSHA1 spelling from spec Example 33', function () {
    // 5.5.2's normative list says xmlenc11#mgf1sha1, but Example 33 in the same
    // section writes xmlenc#MGF1withSHA1. Implementations copied the example.
    var pub = fs.readFileSync(__dirname + '/test-auth0_rsa.pub');
    var sym = require('crypto').randomBytes(32);
    var wrapped = oaep.publicEncryptOaep(pub, sym, { oaepHash: 'sha256', mgf1Hash: 'sha1' });
    var keyInfo = '<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">' +
      '<e:EncryptedKey xmlns:e="http://www.w3.org/2001/04/xmlenc#">' +
      '<e:EncryptionMethod Algorithm="' + RSA_OAEP_11 + '">' +
      '<MGF Algorithm="http://www.w3.org/2001/04/xmlenc#MGF1withSHA1" />' +
      '<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />' +
      '</e:EncryptionMethod>' +
      '<e:CipherData><e:CipherValue>' + wrapped.toString('base64') + '</e:CipherValue></e:CipherData>' +
      '</e:EncryptedKey></KeyInfo>';
    var recovered = xmlenc.decryptKeyInfo(keyInfo, { key: fs.readFileSync(__dirname + '/test-auth0.key') });
    assert.equal(Buffer.compare(Buffer.from(recovered), sym), 0);
  });

  it('never emits the MGF1withSHA1 alias it accepts on decrypt', function () {
    // The alias is decrypt-only: it is not in 5.5.2's normative list, so emitting
    // it would send a non-normative URI to peers. The emit map is derived from the
    // canonical list alone, which is what makes this hold.
    var mgf = require('../lib/mgf-algorithms');
    assert.equal(mgf.MGF_URI_FOR_EMIT['sha1'], 'http://www.w3.org/2009/xmlenc11#mgf1sha1');
    assert.equal(mgf.MGF_ALGORITHMS['http://www.w3.org/2001/04/xmlenc#MGF1withSHA1'], 'sha1');
    Object.keys(mgf.MGF_URI_FOR_EMIT).forEach(function (shortName) {
      assert(mgf.MGF_URI_FOR_EMIT[shortName].indexOf('http://www.w3.org/2009/xmlenc11#mgf1') === 0,
        shortName + ' must emit a normative xmlenc11 URI, got ' + mgf.MGF_URI_FOR_EMIT[shortName]);
    });
  });

  it('rejects keyEncryptionMgf under mgf1p instead of silently ignoring it', function (done) {
    xmlenc.encrypt('x', {
      rsa_pub: fs.readFileSync(__dirname + '/test-auth0_rsa.pub'),
      pem: fs.readFileSync(__dirname + '/test-auth0.pem'),
      encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
      keyEncryptionAlgorithm: RSA_OAEP,
      keyEncryptionDigest: 'sha256',
      keyEncryptionMgf: 'sha256'
    }, function (err) {
      assert(err, 'expected an error');
      assert(/keyEncryptionMgf/.test(err.message));
      done();
    });
  });

  it('accepts keyEncryptionMgf as a full MGF URI', function (done) {
    var options = {
      rsa_pub: fs.readFileSync(__dirname + '/test-auth0_rsa.pub'),
      pem: fs.readFileSync(__dirname + '/test-auth0.pem'),
      encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
      keyEncryptionAlgorithm: RSA_OAEP_11,
      keyEncryptionDigest: 'sha256',
      keyEncryptionMgf: 'http://www.w3.org/2009/xmlenc11#mgf1sha256'
    };
    xmlenc.encrypt('uri form', options, function (err, result) {
      if (err) return done(err);
      assert(result.includes('http://www.w3.org/2009/xmlenc11#mgf1sha256'));
      xmlenc.decrypt(result, { key: fs.readFileSync(__dirname + '/test-auth0.key') }, function (err2, decrypted) {
        if (err2) return done(err2);
        assert.equal(decrypted, 'uri form');
        done();
      });
    });
  });

  it('rejects an unsupported keyEncryptionMgf value', function (done) {
    xmlenc.encrypt('x', {
      rsa_pub: fs.readFileSync(__dirname + '/test-auth0_rsa.pub'),
      pem: fs.readFileSync(__dirname + '/test-auth0.pem'),
      encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
      keyEncryptionAlgorithm: RSA_OAEP_11,
      keyEncryptionDigest: 'sha256',
      keyEncryptionMgf: 'md5'
    }, function (err) {
      assert(err, 'expected an error');
      assert(/keyEncryptionMgf/.test(err.message));
      assert(/md5/.test(err.message));
      done();
    });
  });

  it('rejects MGF with "constructor" to avoid prototype pollution', function (done) {
    xmlenc.encrypt('x', {
      rsa_pub: fs.readFileSync(__dirname + '/test-auth0_rsa.pub'),
      pem: fs.readFileSync(__dirname + '/test-auth0.pem'),
      encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
      keyEncryptionAlgorithm: RSA_OAEP_11,
      keyEncryptionDigest: 'sha256',
      keyEncryptionMgf: 'constructor'
    }, function (err) {
      assert(err, 'expected an error');
      assert(/keyEncryptionMgf/.test(err.message));
      done();
    });
  });

  it('rejects <MGF Algorithm="constructor" /> on decrypt', function () {
    var pub = fs.readFileSync(__dirname + '/test-auth0_rsa.pub');
    var wrapped = oaep.publicEncryptOaep(pub, Buffer.alloc(32), { oaepHash: 'sha256', mgf1Hash: 'sha1' });
    var keyInfo = '<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">' +
      '<e:EncryptedKey xmlns:e="http://www.w3.org/2001/04/xmlenc#">' +
      '<e:EncryptionMethod Algorithm="' + RSA_OAEP_11 + '">' +
      '<MGF Algorithm="constructor" />' +
      '<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />' +
      '</e:EncryptionMethod>' +
      '<e:CipherData><e:CipherValue>' + wrapped.toString('base64') + '</e:CipherValue></e:CipherData>' +
      '</e:EncryptedKey></KeyInfo>';
    assert.throws(function () {
      xmlenc.decryptKeyInfo(keyInfo, { key: fs.readFileSync(__dirname + '/test-auth0.key') });
    }, /mask generation function/);
  });
});

describe('OAEPparams', function () {
  var oaep = require('../lib/oaep');
  var crypto = require('crypto');

  it('decrypts a key wrapped with a non-empty OAEP label', function () {
    var label = Buffer.from('MYLABEL');
    var sym = crypto.randomBytes(32);
    var wrapped = oaep.publicEncryptOaep(fs.readFileSync(__dirname + '/test-auth0_rsa.pub'), sym, {
      oaepHash: 'sha256', mgf1Hash: 'sha1', oaepLabel: label
    });
    var keyInfo = '<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">' +
      '<e:EncryptedKey xmlns:e="http://www.w3.org/2001/04/xmlenc#">' +
      '<e:EncryptionMethod Algorithm="' + RSA_OAEP + '">' +
      '<OAEPparams>' + label.toString('base64') + '</OAEPparams>' +
      '<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />' +
      '</e:EncryptionMethod>' +
      '<e:CipherData><e:CipherValue>' + wrapped.toString('base64') + '</e:CipherValue></e:CipherData>' +
      '</e:EncryptedKey></KeyInfo>';
    var recovered = xmlenc.decryptKeyInfo(keyInfo, { key: fs.readFileSync(__dirname + '/test-auth0.key') });
    assert.equal(Buffer.compare(Buffer.from(recovered), sym), 0);
  });

  it('round trips keyEncryptionOaepParams through encrypt and decrypt', function (done) {
    var xmldom = require('@xmldom/xmldom');
    var xpath = require('xpath');
    xmlenc.encrypt('labelled content', {
      rsa_pub: fs.readFileSync(__dirname + '/test-auth0_rsa.pub'),
      pem: fs.readFileSync(__dirname + '/test-auth0.pem'),
      encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
      keyEncryptionAlgorithm: RSA_OAEP,
      keyEncryptionDigest: 'sha256',
      keyEncryptionOaepParams: Buffer.from('9lWu3Q==', 'base64')
    }, function (err, result) {
      if (err) return done(err);
      // OAEPparams must be in the xenc namespace, not xmldsig, and appear before MGF and DigestMethod.
      var doc = new xmldom.DOMParser().parseFromString(result);
      var encMethod = xpath.select("//*[local-name(.)='EncryptedKey']/*[local-name(.)='EncryptionMethod']", doc)[0];
      var params = xpath.select("*[local-name(.)='OAEPparams']", encMethod);
      assert.equal(params.length, 1, 'OAEPparams element must be present');
      assert.equal(params[0].namespaceURI, 'http://www.w3.org/2001/04/xmlenc#', 'OAEPparams must be in xenc namespace');
      assert.equal(params[0].textContent, '9lWu3Q==', 'OAEPparams value must match');
      // Verify element ordering: OAEPparams comes before DigestMethod
      var children = Array.from(encMethod.childNodes).filter(function (n) { return n.nodeType === 1; });
      var oaepIdx = children.findIndex(function (n) { return n.localName === 'OAEPparams'; });
      var digestIdx = children.findIndex(function (n) { return n.localName === 'DigestMethod'; });
      assert(oaepIdx >= 0 && digestIdx >= 0 && oaepIdx < digestIdx, 'OAEPparams must come before DigestMethod');
      xmlenc.decrypt(result, { key: fs.readFileSync(__dirname + '/test-auth0.key') }, function (err2, decrypted) {
        if (err2) return done(err2);
        assert.equal(decrypted, 'labelled content');
        done();
      });
    });
  });

  it('rejects keyEncryptionOaepParams under rsa-1_5 instead of silently ignoring it', function (done) {
    xmlenc.encrypt('x', {
      rsa_pub: fs.readFileSync(__dirname + '/test-auth0_rsa.pub'),
      pem: fs.readFileSync(__dirname + '/test-auth0.pem'),
      encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
      keyEncryptionAlgorithm: RSA_1_5,
      keyEncryptionOaepParams: Buffer.from('9lWu3Q==', 'base64'),
      disallowEncryptionWithInsecureAlgorithm: false
    }, function (err) {
      assert(err, 'expected an error');
      assert(/keyEncryptionOaepParams/.test(err.message));
      done();
    });
  });
});
