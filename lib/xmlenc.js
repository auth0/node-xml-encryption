var crypto  = require('crypto');
var xmldom  = require('@xmldom/xmldom');
var xpath   = require('xpath');
var utils   = require('./utils');
var oaep    = require('./oaep');

const insecureAlgorithms = [
  //https://www.w3.org/TR/xmlenc-core1/#rsav15note
  'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
  //https://csrc.nist.gov/News/2017/Update-to-Current-Use-and-Deprecation-of-TDEA
  'http://www.w3.org/2001/04/xmlenc#tripledes-cbc',
  //https://www.w3.org/TR/xmlenc-core1/#sec-edata-attacks
  'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
  'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
];

// XML-Enc 1.1 5.5.2. The normative list uses the xmlenc11#mgf1* URIs; the
// xmlenc#MGF1withSHA1 spelling is accepted on decrypt because Example 33 in
// that same section uses it and implementations copied it.
const MGF_ALGORITHMS = Object.assign(Object.create(null), {
  'http://www.w3.org/2009/xmlenc11#mgf1sha1': 'sha1',
  'http://www.w3.org/2009/xmlenc11#mgf1sha224': 'sha224',
  'http://www.w3.org/2009/xmlenc11#mgf1sha256': 'sha256',
  'http://www.w3.org/2009/xmlenc11#mgf1sha384': 'sha384',
  'http://www.w3.org/2009/xmlenc11#mgf1sha512': 'sha512',
  'http://www.w3.org/2001/04/xmlenc#MGF1withSHA1': 'sha1'
});
const MGF_SHORT_NAMES = Object.values(MGF_ALGORITHMS);

function encryptKeyInfoWithScheme(symmetricKey, options, padding, mgf1Hash, callback) {
  const symmetricKeyBuffer = Buffer.isBuffer(symmetricKey) ? symmetricKey : Buffer.from(symmetricKey, 'utf-8');

  try {
    const isOAEP = padding == crypto.constants.RSA_PKCS1_OAEP_PADDING;
    const oaepHash = isOAEP ? options.keyEncryptionDigest : undefined;
    const oaepLabel = options.keyEncryptionOaepParams
      ? (Buffer.isBuffer(options.keyEncryptionOaepParams)
          ? options.keyEncryptionOaepParams
          : Buffer.from(options.keyEncryptionOaepParams, 'base64'))
      : Buffer.alloc(0);
    if (isOAEP && !mgf1Hash) {
      return callback(new Error('mgf1Hash is required for OAEP padding'));
    }
    let encrypted;
    if (isOAEP && (mgf1Hash !== oaepHash || oaepLabel.length > 0)) {
      // Node cannot set MGF1 separately from the OAEP digest, and has no label option.
      encrypted = oaep.publicEncryptOaep(options.rsa_pub, symmetricKeyBuffer, {
        oaepHash: oaepHash,
        mgf1Hash: mgf1Hash,
        oaepLabel: oaepLabel
      });
    } else {
      encrypted = crypto.publicEncrypt({
        key: options.rsa_pub,
        oaepHash: oaepHash,
        padding: padding
      }, symmetricKeyBuffer);
    }
    var base64EncodedEncryptedKey = encrypted.toString('base64');

    var params = {
      encryptedKey:  base64EncodedEncryptedKey,
      encryptionPublicCert: '<X509Data><X509Certificate>' + utils.pemToCert(options.pem.toString()) + '</X509Certificate></X509Data>',
      keyEncryptionMethod: options.keyEncryptionAlgorithm,
      keyEncryptionDigest: options.keyEncryptionDigest,
      keyEncryptionMgf: mgf1Hash,
      keyEncryptionOaepParams: oaepLabel.length ? oaepLabel.toString('base64') : null,
    };

    var result = utils.renderTemplate('keyinfo', params);
    callback(null, result);
  } catch (e) {
    callback(e);
  }
}

function encryptKeyInfo(symmetricKey, options, callback) {
  if (!options)
    return callback(new Error('must provide options'));
  if (!options.rsa_pub)
    return callback(new Error('must provide options.rsa_pub with public key RSA'));
  if (!options.pem)
    return callback(new Error('must provide options.pem with certificate'));

  if (!options.keyEncryptionAlgorithm)
    return callback(new Error('encryption without encrypted key is not supported yet'));
  if (options.disallowEncryptionWithInsecureAlgorithm !== false
    && insecureAlgorithms.indexOf(options.keyEncryptionAlgorithm) >= 0) {
    return callback(new Error('encryption algorithm ' + options.keyEncryptionAlgorithm + 'is not secure'));
  }
  options.keyEncryptionDigest = options.keyEncryptionDigest || 'sha1';

  if (options.keyEncryptionMgf
    && options.keyEncryptionAlgorithm !== 'http://www.w3.org/2009/xmlenc11#rsa-oaep') {
    return callback(new Error('keyEncryptionMgf is only supported with http://www.w3.org/2009/xmlenc11#rsa-oaep; '
      + options.keyEncryptionAlgorithm + ' fixes the mask generation function'));
  }

  switch (options.keyEncryptionAlgorithm) {
    case 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p':
      // MGF1 is fixed to SHA-1 by this identifier (XML-Enc 1.1 5.5.2).
      return encryptKeyInfoWithScheme(symmetricKey, options, crypto.constants.RSA_PKCS1_OAEP_PADDING, 'sha1', callback);

    case 'http://www.w3.org/2009/xmlenc11#rsa-oaep': {
      // Normalize keyEncryptionMgf to a short digest name.
      let mgf1Hash = options.keyEncryptionMgf || 'sha1';
      if (MGF_ALGORITHMS[mgf1Hash]) {
        // It's a full URI, map to short name.
        mgf1Hash = MGF_ALGORITHMS[mgf1Hash];
      } else if (!MGF_SHORT_NAMES.includes(mgf1Hash)) {
        // It's neither a known URI nor a valid short name.
        return callback(new Error('keyEncryptionMgf value ' + mgf1Hash + ' is not supported'));
      }
      return encryptKeyInfoWithScheme(symmetricKey, options, crypto.constants.RSA_PKCS1_OAEP_PADDING, mgf1Hash, callback);
    }

    case 'http://www.w3.org/2001/04/xmlenc#rsa-1_5':
      utils.warnInsecureAlgorithm(options.keyEncryptionAlgorithm, options.warnInsecureAlgorithm);
      return encryptKeyInfoWithScheme(symmetricKey, options, crypto.constants.RSA_PKCS1_PADDING, undefined, callback);

    default:
      return callback(new Error('encryption key algorithm not supported'));
  }
}

function encrypt(content, options, callback) {
  if (!options)
    return callback(new Error('must provide options'));
  if (!content)
    return callback(new Error('must provide content to encrypt'));
  if (!options.rsa_pub)
    return callback(new Error('rsa_pub option is mandatory and you should provide a valid RSA public key'));
  if (!options.pem)
    return callback(new Error('pem option is mandatory and you should provide a valid x509 certificate encoded as PEM'));
  if (options.disallowEncryptionWithInsecureAlgorithm !== false) {
    if (insecureAlgorithms.indexOf(options.keyEncryptionAlgorithm) >= 0) {
      return callback(new Error('encryption algorithm ' + options.keyEncryptionAlgorithm + ' is not secure'));
    }
    if (insecureAlgorithms.indexOf(options.encryptionAlgorithm) >= 0) {
      return callback(new Error('encryption algorithm ' + options.encryptionAlgorithm + ' is not secure'));
    }
  }
  options.input_encoding = options.input_encoding || 'utf8';

  function generate_symmetric_key(cb) {
    switch (options.encryptionAlgorithm) {
      case 'http://www.w3.org/2001/04/xmlenc#aes128-cbc':
        utils.warnInsecureAlgorithm(options.encryptionAlgorithm, options.warnInsecureAlgorithm);
        crypto.randomBytes(16, cb); // generate a symmetric random key 16 bytes length
        break;
      case 'http://www.w3.org/2001/04/xmlenc#aes256-cbc':
        utils.warnInsecureAlgorithm(options.encryptionAlgorithm, options.warnInsecureAlgorithm);
        crypto.randomBytes(32, cb); // generate a symmetric random key 32 bytes length
        break;
      case 'http://www.w3.org/2009/xmlenc11#aes128-gcm':
        crypto.randomBytes(16, cb); // generate a symmetric random key 16 bytes length
        break;
      case 'http://www.w3.org/2009/xmlenc11#aes256-gcm':
        crypto.randomBytes(32, cb); // generate a symmetric random key 32 bytes length
        break;
      case 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc':
        utils.warnInsecureAlgorithm(options.encryptionAlgorithm, options.warnInsecureAlgorithm);
        crypto.randomBytes(24, cb); // generate a symmetric random key 24 bytes (192 bits) length
        break;
      default:
        crypto.randomBytes(32, cb); // generate a symmetric random key 32 bytes length
    }
  }

  function encrypt_content(symmetricKey, cb) {
    switch (options.encryptionAlgorithm) {
      case 'http://www.w3.org/2001/04/xmlenc#aes128-cbc':
        utils.warnInsecureAlgorithm(options.encryptionAlgorithm, options.warnInsecureAlgorithm);
        encryptWithAlgorithm('aes-128-cbc', symmetricKey, 16, content, options.input_encoding, function (err, encryptedContent) {
          if (err) return cb(err);
          cb(null, encryptedContent);
        });
        break;
      case 'http://www.w3.org/2001/04/xmlenc#aes256-cbc':
        utils.warnInsecureAlgorithm(options.encryptionAlgorithm, options.warnInsecureAlgorithm);
        encryptWithAlgorithm('aes-256-cbc', symmetricKey, 16, content, options.input_encoding, function (err, encryptedContent) {
          if (err) return cb(err);
          cb(null, encryptedContent);
        });
        break;
      case 'http://www.w3.org/2009/xmlenc11#aes128-gcm':
        encryptWithAlgorithm('aes-128-gcm', symmetricKey, 12, content, options.input_encoding, function (err, encryptedContent) {
          if (err) return cb(err);
          cb(null, encryptedContent);
        });
        break;
      case 'http://www.w3.org/2009/xmlenc11#aes256-gcm':
        encryptWithAlgorithm('aes-256-gcm', symmetricKey, 12, content, options.input_encoding, function (err, encryptedContent) {
          if (err) return cb(err);
          cb(null, encryptedContent);
        });
        break;
      case 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc':
        utils.warnInsecureAlgorithm(options.encryptionAlgorithm, options.warnInsecureAlgorithm);
        encryptWithAlgorithm('des-ede3-cbc', symmetricKey, 8, content, options.input_encoding, function (err, encryptedContent) {
          if (err) return cb(err);
          cb(null, encryptedContent);
        });
        break;
      default:
        cb(new Error('encryption algorithm not supported'));
    }
  }

  function encrypt_key(symmetricKey, encryptedContent, cb) {
    encryptKeyInfo(symmetricKey, options, function(err, keyInfo) {
      if (err) return cb(err);
      var result = utils.renderTemplate('encrypted-key', {
        encryptedContent: encryptedContent.toString('base64'),
        keyInfo: keyInfo,
        contentEncryptionMethod: options.encryptionAlgorithm
      });

      cb(null, result);
    });
  }


  generate_symmetric_key(function (genKeyError, symmetricKey) {
    if (genKeyError) {
      return callback(genKeyError);
    }

    encrypt_content(symmetricKey, function(encryptContentError, encryptedContent) {
      if (encryptContentError) {
        return callback(encryptContentError);
      }

      encrypt_key(symmetricKey, encryptedContent, function (encryptKeyError, result) {
        if (encryptKeyError) {
          return callback(encryptKeyError);
        }

        callback(null, result);
      });

    });

  });
}

function decrypt(xml, options, callback) {
  if (!options)
    return callback(new Error('must provide options'));
  if (!xml)
    return callback(new Error('must provide XML to encrypt'));
  if (!options.key)
    return callback(new Error('key option is mandatory and you should provide a valid RSA private key'));
  try {
    var doc = typeof xml === 'string' ? new xmldom.DOMParser().parseFromString(xml) : xml;

    var symmetricKey = decryptKeyInfo(doc, options);
    var encryptionMethod = xpath.select("//*[local-name(.)='EncryptedData']/*[local-name(.)='EncryptionMethod']", doc)[0];
    var encryptionAlgorithm = encryptionMethod.getAttribute('Algorithm');

    if (options.disallowDecryptionWithInsecureAlgorithm !== false 
      && insecureAlgorithms.indexOf(encryptionAlgorithm) >= 0) {
      return callback(new Error('encryption algorithm ' + encryptionAlgorithm + ' is not secure, fail to decrypt'));
    }
    var encryptedContent = xpath.select("//*[local-name(.)='EncryptedData']/*[local-name(.)='CipherData']/*[local-name(.)='CipherValue']", doc)[0];

    var encrypted = Buffer.from(encryptedContent.textContent, 'base64');
    switch (encryptionAlgorithm) {
      case 'http://www.w3.org/2001/04/xmlenc#aes128-cbc':
        utils.warnInsecureAlgorithm(encryptionAlgorithm, options.warnInsecureAlgorithm);
        return callback(null, decryptWithAlgorithm('aes-128-cbc', symmetricKey, 16, encrypted));
      case 'http://www.w3.org/2001/04/xmlenc#aes256-cbc':
        utils.warnInsecureAlgorithm(encryptionAlgorithm, options.warnInsecureAlgorithm);
        return callback(null, decryptWithAlgorithm('aes-256-cbc', symmetricKey, 16, encrypted));
      case 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc':
        utils.warnInsecureAlgorithm(encryptionAlgorithm, options.warnInsecureAlgorithm);
        return callback(null, decryptWithAlgorithm('des-ede3-cbc', symmetricKey, 8, encrypted));
      case 'http://www.w3.org/2009/xmlenc11#aes128-gcm':
        return callback(null, decryptWithAlgorithm('aes-128-gcm', symmetricKey, 12, encrypted));
      case 'http://www.w3.org/2009/xmlenc11#aes256-gcm':
        return callback(null, decryptWithAlgorithm('aes-256-gcm', symmetricKey, 12, encrypted));
      default:
        return callback(new Error('encryption algorithm ' + encryptionAlgorithm + ' not supported'));
    }
  } catch (e) {
    return callback(e);
  }
}

function decryptKeyInfo(doc, options) {
  if (typeof doc === 'string') doc = new xmldom.DOMParser().parseFromString(doc);

  var keyRetrievalMethodUri;
  var keyInfo = xpath.select("//*[local-name(.)='KeyInfo' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']", doc)[0];
  if (!keyInfo) {
    keyInfo = xpath.select("//*[local-name(.)='EncryptedData']/*[local-name(.)='KeyInfo']", doc)[0];
  }
  var keyEncryptionMethod = xpath.select("//*[local-name(.)='KeyInfo']/*[local-name(.)='EncryptedKey']/*[local-name(.)='EncryptionMethod']", doc)[0];

  if (!keyEncryptionMethod) { // try with EncryptedData->KeyInfo->RetrievalMethod
    var keyRetrievalMethod = xpath.select("//*[local-name(.)='EncryptedData']/*[local-name(.)='KeyInfo']/*[local-name(.)='RetrievalMethod']", doc)[0];
    keyRetrievalMethodUri = keyRetrievalMethod ? keyRetrievalMethod.getAttribute('URI') : null;
    keyEncryptionMethod = keyRetrievalMethodUri ? xpath.select("//*[local-name(.)='EncryptedKey' and @Id='" + keyRetrievalMethodUri.substring(1) + "']/*[local-name(.)='EncryptionMethod']", doc)[0] : null;
  }

  if (!keyEncryptionMethod) {
    throw new Error('cant find encryption algorithm');
  }

  let oaepHash = 'sha1';
  // Resolve DigestMethod relative to the EncryptionMethod we already located,
  // not by an absolute path: with EncryptedData/KeyInfo/RetrievalMethod the
  // EncryptedKey lives outside KeyInfo and an anchored XPath finds nothing.
  const keyDigestMethod = xpath.select("./*[local-name(.)='DigestMethod']", keyEncryptionMethod)[0];
  if (keyDigestMethod) {
    const keyDigestMethodAlgorithm = keyDigestMethod.getAttribute('Algorithm');
    switch (keyDigestMethodAlgorithm) {
      case 'http://www.w3.org/2001/04/xmlenc#sha256':
      case 'http://www.w3.org/2000/09/xmldsig#sha256': // backwards compatibility for previous wrong usage
        oaepHash = 'sha256';
        break;
      case 'http://www.w3.org/2001/04/xmlenc#sha512':
      case 'http://www.w3.org/2000/09/xmldsig#sha512': // backwards compatibility for previous wrong usage
        oaepHash = 'sha512';
        break;
    }
  }

  var keyEncryptionAlgorithm = keyEncryptionMethod.getAttribute('Algorithm');
  if (options.disallowDecryptionWithInsecureAlgorithm !== false
    && insecureAlgorithms.indexOf(keyEncryptionAlgorithm) >= 0) {
    throw new Error('encryption algorithm ' + keyEncryptionAlgorithm + ' is not secure, fail to decrypt');
  }
  var encryptedKey = keyRetrievalMethodUri ?
    xpath.select("//*[local-name(.)='EncryptedKey' and @Id='" + keyRetrievalMethodUri.substring(1) + "']/*[local-name(.)='CipherData']/*[local-name(.)='CipherValue']", keyInfo)[0] :
    xpath.select("//*[local-name(.)='CipherValue']", keyInfo)[0];

  // Read the OAEP label from the optional OAEPparams element (XML-Enc 1.1 5.5.2).
  const oaepParams = xpath.select("./*[local-name(.)='OAEPparams']", keyEncryptionMethod)[0];
  const oaepLabel = oaepParams ? Buffer.from(oaepParams.textContent, 'base64') : Buffer.alloc(0);

  switch (keyEncryptionAlgorithm) {
    case 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p':
      // The identifier fixes MGF1 to SHA-1 (XML-Enc 1.1 5.5.2); DigestMethod
      // selects only the OAEP message digest. An xenc11:MGF child is a MUST NOT.
      if (xpath.select("./*[local-name(.)='MGF']", keyEncryptionMethod)[0]) {
        throw new Error('MGF element must not be present with ' + keyEncryptionAlgorithm);
      }
      return decryptKeyInfoWithScheme(encryptedKey, options, crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash, 'sha1', oaepLabel);

    case 'http://www.w3.org/2009/xmlenc11#rsa-oaep': {
      // MGF1 comes from the optional xenc11:MGF child; default MGF1-SHA1.
      const mgfElement = xpath.select("./*[local-name(.)='MGF']", keyEncryptionMethod)[0];
      let mgf1Hash = 'sha1';
      if (mgfElement) {
        const mgfAlgorithm = mgfElement.getAttribute('Algorithm');
        mgf1Hash = MGF_ALGORITHMS[mgfAlgorithm];
        if (!mgf1Hash) {
          throw new Error('mask generation function ' + mgfAlgorithm + ' not supported');
        }
      }
      return decryptKeyInfoWithScheme(encryptedKey, options, crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash, mgf1Hash, oaepLabel);
    }

    case 'http://www.w3.org/2001/04/xmlenc#rsa-1_5':
      utils.warnInsecureAlgorithm(keyEncryptionAlgorithm, options.warnInsecureAlgorithm);
      return decryptKeyInfoWithScheme(encryptedKey, options, crypto.constants.RSA_PKCS1_PADDING);
    default:
      throw new Error('key encryption algorithm ' + keyEncryptionAlgorithm + ' not supported');
  }
}

function decryptKeyInfoWithScheme(encryptedKey, options, padding, oaepHash, mgf1Hash, oaepLabel) {
  const key = Buffer.from(encryptedKey.textContent, 'base64');
  const label = oaepLabel || Buffer.alloc(0);
  if (padding === crypto.constants.RSA_PKCS1_OAEP_PADDING && !mgf1Hash) {
    throw new Error('mgf1Hash is required for OAEP padding');
  }
  // Node's privateDecrypt has no label option, so a non-empty label also needs the shim.
  const needsShim = padding === crypto.constants.RSA_PKCS1_OAEP_PADDING
    && (mgf1Hash !== oaepHash || label.length > 0);
  if (!needsShim) {
    const decrypted = crypto.privateDecrypt({ key: options.key, padding, oaepHash }, key);
    return Buffer.from(decrypted, 'binary');
  }
  return oaep.privateDecryptOaep(options.key, key, { oaepHash, mgf1Hash, oaepLabel: label });
}

function encryptWithAlgorithm(algorithm, symmetricKey, ivLength, content, encoding, callback) {
  // create a random iv for algorithm
  crypto.randomBytes(ivLength, function(err, iv) {
    if (err) return callback(err);

    var cipher = crypto.createCipheriv(algorithm, symmetricKey, iv);
    // encrypted content
    var encrypted = cipher.update(content, encoding, 'binary') + cipher.final('binary');
    var authTag = algorithm.slice(-3) === "gcm" ? cipher.getAuthTag() : Buffer.from("");
    //Format mentioned: https://www.w3.org/TR/xmlenc-core1/#sec-AES-GCM
    var r = Buffer.concat([iv, Buffer.from(encrypted, 'binary'), authTag]);
    return callback(null, r);
  });
}

function decryptWithAlgorithm(algorithm, symmetricKey, ivLength, content) {
  var decipher = crypto.createDecipheriv(algorithm, symmetricKey, content.slice(0,ivLength));
  decipher.setAutoPadding(false);

  if (algorithm.slice(-3) === "gcm") {
    decipher.setAuthTag(content.slice(-16));
    content = content.slice(0,-16);
  }
  var decrypted = decipher.update(content.slice(ivLength), null, 'binary') + decipher.final('binary');

if (algorithm.slice(-3) !== "gcm") {
  // Remove padding bytes equal to the value of the last byte of the returned data.
  // Padding for GCM not required per: https://www.w3.org/TR/xmlenc-core1/#sec-AES-GCM
  var padding = decrypted.charCodeAt(decrypted.length - 1);
  if (1 <= padding && padding <= ivLength) {
    decrypted = decrypted.substr(0, decrypted.length - padding);
  } else {
    callback(new Error('padding length invalid'));
    return;
  }
}

  return Buffer.from(decrypted, 'binary').toString('utf8');
}

exports = module.exports = {
  decrypt: decrypt,
  encrypt: encrypt,
  encryptKeyInfo: encryptKeyInfo,
  decryptKeyInfo: decryptKeyInfo
};
