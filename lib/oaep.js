var crypto = require('crypto');

// CRYPTO MODULE (non-FIPS-validated)
// This file hand-rolls the RSA-OAEP padding (EME-OAEP encode/decode, RFC 8017
// §7.1) in JavaScript. It exists only to express the OAEP-digest / MGF1-digest combinations
// that Node's `crypto` cannot. Because the padding is computed here rather than inside OpenSSL,
// this is not a FIPS valid code path.

function assertShimAllowed() {
  if (crypto.getFips?.()) {
    var err = new Error('unsupported cryptographic operation');
    err.code = 'ERR_XMLENC_FIPS_UNSUPPORTED';
    throw err;
  }
}

// MGF1 mask generation function (RFC 8017 B.2.1).
function mgf1(seed, length, hash) {
  var hLen = crypto.createHash(hash).digest().length;
  var out = Buffer.alloc(Math.ceil(length / hLen) * hLen);
  var counter = Buffer.alloc(4);
  for (var i = 0; i * hLen < length; i++) {
    counter.writeUInt32BE(i, 0);
    crypto.createHash(hash).update(seed).update(counter).digest().copy(out, i * hLen);
  }
  return out.subarray(0, length);
}

function xor(a, b) {
  var out = Buffer.allocUnsafe(a.length);
  for (var i = 0; i < a.length; i++) {
    out[i] = a[i] ^ b[i];
  }
  return out;
}

function decodingError() {
  var err = new Error('oaep decoding error');
  err.code = 'ERR_OSSL_RSA_OAEP_DECODING_ERROR';
  return err;
}

// EME-OAEP-DECODE (RFC 8017 7.1.2) with the message digest and the MGF1 digest
// chosen independently. Node's privateDecrypt cannot express that combination:
// it only sets the OAEP digest, and OpenSSL then defaults MGF1 to match it.
function privateDecryptOaep(privateKey, ciphertext, options) {
  assertShimAllowed();
  var opts = options || {};
  var oaepHash = opts.oaepHash || 'sha1';
  var mgf1Hash = opts.mgf1Hash || oaepHash;
  var label = opts.oaepLabel || Buffer.alloc(0);

  // Parse key before masking errors — operational failures (bad PEM, public-key-for-private)
  // must surface, not masquerade as OAEP decode failures.
  var keyObj = crypto.createPrivateKey(privateKey);
  var k = Math.ceil(keyObj.asymmetricKeyDetails.modulusLength / 8);
  // Ciphertext length comes from the document, so keep the failure generic.
  if (ciphertext.length !== k) throw decodingError();

  var em;
  try {
    em = crypto.privateDecrypt(
      { key: keyObj, padding: crypto.constants.RSA_NO_PADDING },
      ciphertext
    );
  } catch (e) {
    // Ciphertext ≥ modulus fails before OAEP decode starts. Also from the
    // document, so stay generic.
    throw decodingError();
  }

  var hLen = crypto.createHash(oaepHash).digest().length;
  if (em.length < 2 * hLen + 2) throw decodingError();

  var maskedSeed = em.subarray(1, 1 + hLen);
  var maskedDB = em.subarray(1 + hLen);
  var seed = xor(maskedSeed, mgf1(maskedDB, hLen, mgf1Hash));
  var db = xor(maskedDB, mgf1(seed, maskedDB.length, mgf1Hash));
  var lHash = crypto.createHash(oaepHash).update(label).digest();

  // Accumulate every failure condition, then throw one generic error. Do not
  // branch out early and do not report which check failed: the RFC 8017
  // 7.1.2 checks must be indistinguishable from outside.
  var bad = em[0] | (crypto.timingSafeEqual(db.subarray(0, hLen), lHash) ? 0 : 1);
  var found = 0;
  var messageStart = 0;
  for (var i = hLen; i < db.length; i++) {
    var isZero = ((db[i] - 1) >>> 31) & 1;
    var isOne = (((db[i] ^ 1) - 1) >>> 31) & 1;
    var first = isOne & (found ^ 1);
    messageStart |= first * (i + 1);
    found |= isOne;
    bad |= (found ^ 1) & (isZero ^ 1);
  }
  if (bad || !found) throw decodingError();

  return Buffer.from(db.subarray(messageStart));
}

// EME-OAEP-ENCODE (RFC 8017 7.1.1) followed by the raw RSA public operation.
function publicEncryptOaep(publicKey, message, options) {
  assertShimAllowed();
  var opts = options || {};
  var oaepHash = opts.oaepHash || 'sha1';
  var mgf1Hash = opts.mgf1Hash || oaepHash;
  var label = opts.oaepLabel || Buffer.alloc(0);

  var key = crypto.createPublicKey(publicKey);
  var k = Math.ceil(key.asymmetricKeyDetails.modulusLength / 8);
  var hLen = crypto.createHash(oaepHash).digest().length;
  var msg = Buffer.isBuffer(message) ? message : Buffer.from(message);
  if (msg.length > k - 2 * hLen - 2) {
    throw new Error('message too long for the given key size');
  }

  var lHash = crypto.createHash(oaepHash).update(label).digest();
  var db = Buffer.concat([
    lHash,
    Buffer.alloc(k - msg.length - 2 * hLen - 2),
    Buffer.from([0x01]),
    msg
  ]);
  var seed = crypto.randomBytes(hLen);
  var maskedDB = xor(db, mgf1(seed, db.length, mgf1Hash));
  var maskedSeed = xor(seed, mgf1(maskedDB, hLen, mgf1Hash));
  var em = Buffer.concat([Buffer.alloc(1), maskedSeed, maskedDB]);

  return crypto.publicEncrypt(
    { key: key, padding: crypto.constants.RSA_NO_PADDING },
    em
  );
}

module.exports = {
  mgf1: mgf1,
  publicEncryptOaep: publicEncryptOaep,
  privateDecryptOaep: privateDecryptOaep
};
