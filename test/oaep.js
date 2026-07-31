var assert = require('assert');
var crypto = require('crypto');
var oaep = require('../lib/oaep');

// Throwaway 2048-bit key + ciphertext from the ESD-63620 repro. Produced by:
//   openssl pkeyutl -encrypt -pubin -inkey pub.pem -in key.bin \
//     -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha1
var VECTOR_PLAINTEXT = 'AES-128-key-1234';
var VECTOR_KEY = Buffer.from(
  'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2UUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktjd2dnU2pBZ0VBQW9JQkFRQzA5QmY1NTRXR0VxRXYKMmZyUWxOUG9ycWRMbld5RVAyTGlybGwvekZuUHFnK0c5RkdxYnNNb3o3UG1CUDRpZlRhVFRtSkViaUx1ajkyWQpQM3FieU9JUmN6MkFZQXJkZlE3M0RiSXhYaUZsazNObjlvVnRISVJUcHVvZkwzc2FkVlozMGg5c3JVeTZ4N0Z1ClZvL0ErNDJlSEVRNEdhaGJOSjJsMlh2QU5ydGQwUG5jNlc2MS9pVTdQK3Z4WDJyM0Fqb2VLMjNTWVRxbTkxRTkKMlN0WmVKQjJuSm4rSGxaamV6WTVUblhCZy9HRmFCZGNvR1JMb1diYzFsV2Q0SHNYa1BuVExyTW5UL0xiV1pQZQo4QVpyU253R1Fpa3dud245ZjF3K01ZQ1h6QU0yNWE4STkrZXRacEl0cFN5VUVtWE9yMnEzRkVkMG5RUUVzMHNFCmkrbENlaW5oQWdNQkFBRUNnZ0VBRUpDdDV6YytIblZ6SXczSjY3Rk1LdWRlTWtwaGhrUEZPaW9xMEV1MVJ4RHkKNWZCVXo0emZPY3UxMU05Tk1ud1M5RzQvQ2JPcFoveHNsVVR1WlBlQlZvYWRzVFJabWtnYUNCek5YTDZZd1JNOApBOTdwL1FDWXpvMmZyaVlyRjFONWpIT0VZKzhEY0svYU90Y2F4dGhnY1FKMmJrcFBBclp3M2g5b09FTHFhUjZTClJyNDgxSUZtS0JNdmhyVUQxVFU0MG5jWG43MTdvazlxalR4bFNuOElONElxSmVMTDFPTkFTMDlNSkhISTZPdG8KbHRZUjNWc1RFdE9YTGNsQ2ZubU5ZT2xpeVgrL1VoMTZBak0rSlJmOFRNL2lDYjNkUGFxMyt4UUFCL1oxRnZPZAo0UEFpa01LNVFTc09jdHhxYThwbm10MUlLK1N4MEZ0aUIweThzbWdYM3dLQmdRRHIyNmxLMlIwbmRpWVZDK3hLCjB2SmxYZ0FZeG9TU1IxOS9EdEFQbDdNMkFVVFRzblVFNmlpSCtDbU1ZK1k5Qm0wblkrNGsveThNUG9sdHZ5OUsKQ1ZVT21Ka0hFY3IvZmo3WHl2OEdkTTJSeXVQOHFhRVZxUlh5WU9PMzM5OUt0NzBFb3FFWVJsS0MxQllXcTVWcQovRExURXphSEowSHFXSk85QjB5eW00cDJId0tCZ1FERWFCdEZGN0NqbG1lMVVjUXRDZ0pqZnZPVWF6UTQ3WGdxClpkNTZ6emcyWm5vejZjYzkvTE40WnV5OC8rcFRYcS9GL3E5RjZtb1pyYktHVDBlNFg4dlVtQVZxd3NmQ01TOGcKTWk4Ui8zeGRZdG54Ly9IbW5DUmpYYTJTOUoraWU1Wks3RHpZWGl0Vi9yamEwRHhvWG9RMm82TG9URXQ1WVNTdQpFY2dEclNkZi93S0JnQXZ5dk1qRjV1d3cyQTBJNVplRXlETEthRWJaQjY1QlgxMFlhd0hmTlh6dTQ0VzE3S2VyCkZSS09SOHlNNHdVRVpsTXdoTWZyQlg4aFMrVDdZbkhsdHlGZUthSnFERmFWRnFubjVyTjFCMVR6YWtsS2JwYWkKVWpKTkpqd1NZMFZ0dVcyYXIzNkRVWHEvTTc5Q1FmZUJmekdpTDRqNVBDV2JCeUQwVmJaV210VVJBb0dBY3ZncAo5bUR1c21QSm8zY1FxZml3KzBNR0hMeEFYbzZMaCs0SHRNWDJOc24wQU1sNUt3endsYXRTS3pSM0c0UlN5a2pTCm1zK2tlaEdXYms2Y1FnNDVoK0hSVWZSZzhJalArRDNJRmZZQys3dHdydHRPNDlwRTVyR2dlR1NmeVlJa3NRam0KZVJWdXNyRWZ6bDZVN2RkZDk0b0VRNHpkcFZpN0d2WW5xaGRDOUVzQ2dZRUFwSkJ1SEpFZXYwd1lxUStnNERzVwpxZTVQYWJOY1dVaDJrNUswMGwza0lmMlpweVdWRWs5bnhRVzJIOFVmNHNVc0d0VTBvMmUycEtUanJ1WDRWcVR5CitoeWxrOXZEam1MU29CenFEREU4bFdOK1llU3hBYzJ0WnE2TnpmT0FPZGdHOVN1ODI0MDlEcUtuR1RlQzlKKzAKWHJ6Z21WOGp5K013cU9kQXJ2QXJ0MXM9Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K',
  'base64'
).toString('utf8');
var VECTOR_CT = Buffer.from(
  'fcAWGHe0HIxC3LcLBwwrkts3005XTSznQZTZZU6EiLOSh/fAfPoe0vF60RcK0IYGW1oDUfuwCl3W+C3HOPTRvFGHiI6AfKCKkj8pTna6WuAZP5x4lBdSKxkIoECgBp+GYko2TMlRn6aW0mOhMCw60P1lT5x93blbbYf4nh0reOtODA8VQBCHnS0wu+qFqIzG/x2UgIbrasnlHo45UlbxdfpOYR08ckKZZrltMZrLcoQnTgrwevwafOg9OvfpY9Kw5Aml+aBhdsabr2aQC5quE6nho0ar/QobPmG5+WzEB5eHn59fTQExDdV2KDcyi7E8xACOjkFFWr+VZmf6t1l59Q==',
  'base64'
);

describe('oaep', function () {
  describe('privateDecryptOaep', function () {
    it('decrypts an OpenSSL OAEP(sha256)/MGF1(sha1) ciphertext', function () {
      var pt = oaep.privateDecryptOaep(VECTOR_KEY, VECTOR_CT, {
        oaepHash: 'sha256',
        mgf1Hash: 'sha1'
      });
      assert.equal(pt.toString('utf8'), VECTOR_PLAINTEXT);
    });

    it('rejects the same ciphertext when MGF1 is wrong', function () {
      assert.throws(function () {
        oaep.privateDecryptOaep(VECTOR_KEY, VECTOR_CT, {
          oaepHash: 'sha256',
          mgf1Hash: 'sha256'
        });
      }, /oaep decoding error/);
    });

    it('rejects random bytes', function () {
      assert.throws(function () {
        oaep.privateDecryptOaep(VECTOR_KEY, crypto.randomBytes(256), {
          oaepHash: 'sha256',
          mgf1Hash: 'sha1'
        });
      }, /oaep decoding error/);
    });

    it('sets code ERR_OSSL_RSA_OAEP_DECODING_ERROR on failure', function () {
      try {
        oaep.privateDecryptOaep(VECTOR_KEY, crypto.randomBytes(256), { oaepHash: 'sha256', mgf1Hash: 'sha1' });
        assert.fail('should have thrown');
      } catch (e) {
        assert.equal(e.code, 'ERR_OSSL_RSA_OAEP_DECODING_ERROR');
      }
    });
  });

  describe('mgf1', function () {
    it('matches the RFC 8017 counter construction for one block', function () {
      var seed = Buffer.from('abc');
      var ctr = Buffer.alloc(4); // i = 0
      var expected = crypto.createHash('sha1').update(seed).update(ctr).digest();
      assert.equal(oaep.mgf1(seed, 20, 'sha1').toString('hex'), expected.toString('hex'));
    });

    it('spans multiple blocks and truncates to the requested length', function () {
      var out = oaep.mgf1(Buffer.from('seed'), 50, 'sha1');
      assert.equal(out.length, 50);
    });
  });

  describe('round trips', function () {
    var fs = require('fs');
    var pub = fs.readFileSync(__dirname + '/test-auth0_rsa.pub');
    var key = fs.readFileSync(__dirname + '/test-auth0.key');
    var combos = [
      ['sha256', 'sha1'],
      ['sha512', 'sha1'],
      ['sha1', 'sha256'],
      ['sha384', 'sha256'],
      ['sha256', 'sha256']
    ];

    combos.forEach(function (combo) {
      var oaepHash = combo[0];
      var mgf1Hash = combo[1];
      // 2048-bit key => k = 256 bytes; longest legal message is k - 2*hLen - 2.
      var hLen = crypto.createHash(oaepHash).digest().length;
      [0, 1, 17, 256 - 2 * hLen - 2].forEach(function (len) {
        it('round trips oaep=' + oaepHash + ' mgf1=' + mgf1Hash + ' len=' + len, function () {
          var msg = crypto.randomBytes(len);
          var ct = oaep.publicEncryptOaep(pub, msg, { oaepHash: oaepHash, mgf1Hash: mgf1Hash });
          var pt = oaep.privateDecryptOaep(key, ct, { oaepHash: oaepHash, mgf1Hash: mgf1Hash });
          assert.equal(Buffer.compare(pt, msg), 0);
        });
      });
    });

    it('rejects a message longer than the key allows', function () {
      assert.throws(function () {
        oaep.publicEncryptOaep(pub, crypto.randomBytes(256), { oaepHash: 'sha256' });
      }, /message too long/);
    });

    it('round trips a non-empty oaepLabel and rejects the wrong label', function () {
      var label = Buffer.from('MYLABEL');
      var ct = oaep.publicEncryptOaep(pub, Buffer.from('labelled'), { oaepHash: 'sha256', mgf1Hash: 'sha1', oaepLabel: label });
      var pt = oaep.privateDecryptOaep(key, ct, { oaepHash: 'sha256', mgf1Hash: 'sha1', oaepLabel: label });
      assert.equal(pt.toString(), 'labelled');
      assert.throws(function () {
        oaep.privateDecryptOaep(key, ct, { oaepHash: 'sha256', mgf1Hash: 'sha1' });
      }, /oaep decoding error/);
    });
  });
});
