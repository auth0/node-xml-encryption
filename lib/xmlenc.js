var crypto = require('crypto');
var async  = require('async');
var xmldom = require('xmldom');
var xpath  = require('xpath');
var utils  = require('./utils');
var pki = require('node-forge').pki;

function encryptKeyInfoWithScheme(symmetricKey, options, scheme, callback) {
  var rsa_pub = pki.publicKeyFromPem(options.rsa_pub);
  var encrypted = rsa_pub.encrypt(symmetricKey.toString('binary'), scheme); 
  var base64EncodedEncryptedKey = new Buffer(encrypted, 'binary').toString('base64');
  
  var params = {
    encryptedKey:  base64EncodedEncryptedKey, 
    encryptionPublicCert: '<X509Data><X509Certificate>' + utils.pemToCert(options.pem.toString()) + '</X509Certificate></X509Data>', 
    keyEncryptionMethod: options.keyEncryptionAlgorighm
  };
  
  var result = utils.renderTemplate('keyinfo', params);

  return callback(null, result);     
}

function encryptKeyInfo(symmetricKey, options, callback) {
  if (!options)
    return callback(new Error('must provide options'));
  if (!options.rsa_pub)
    return callback(new Error('must provide options.rsa_pub with public key RSA'));
  if (!options.pem)
    return callback(new Error('must provide options.pem with certificate'));
  
  if (!options.keyEncryptionAlgorighm)
    return callback(new Error('encryption without encrypted key is not supported yet'));

  switch (options.keyEncryptionAlgorighm) {
    case 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p':
      return encryptKeyInfoWithScheme(symmetricKey, options, 'RSA-OAEP', callback)

    case 'http://www.w3.org/2001/04/xmlenc#rsa-1_5':
      return encryptKeyInfoWithScheme(symmetricKey, options, 'RSAES-PKCS1-V1_5', callback)

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

  async.waterfall([
    function generate_symmetric_key(cb) {
      switch (options.encryptionAlgorithm) {
        case 'http://www.w3.org/2001/04/xmlenc#aes128-cbc':
          crypto.randomBytes(16, cb); // generate a symmetric random key 16 bytes length
          break;
        case 'http://www.w3.org/2001/04/xmlenc#aes256-cbc':
          crypto.randomBytes(32, cb); // generate a symmetric random key 32 bytes length
          break;
        case 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc':
          crypto.randomBytes(24, cb); // generate a symmetric random key 24 bytes (192 bits) length
          break;
        default:
          crypto.randomBytes(32, cb); // generate a symmetric random key 32 bytes length
      }
    },
    function encrypt_content(symmetricKey, cb) {
      switch (options.encryptionAlgorithm) {
        case 'http://www.w3.org/2001/04/xmlenc#aes128-cbc':
          encryptWithAlgorithm('aes-128-cbc', symmetricKey, 16, content, options.input_encoding, function (err, encryptedContent) {
            if (err) return cb(err);
            cb(null, symmetricKey, encryptedContent);
          });
          break;
        case 'http://www.w3.org/2001/04/xmlenc#aes256-cbc':
          encryptWithAlgorithm('aes-256-cbc', symmetricKey, 16, content, options.input_encoding, function (err, encryptedContent) {
            if (err) return cb(err);
            cb(null, symmetricKey, encryptedContent);
          });
          break;
        case 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc':
          encryptWithAlgorithm('des-ede3-cbc', symmetricKey, 8, content, options.input_encoding, function (err, encryptedContent) {
            if (err) return cb(err);
            cb(null, symmetricKey, encryptedContent);
          });
          break;
        default:
          cb(new Error('encryption algorithm not supported'));
      }
    },
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
  ], callback);
}

function decrypt(xml, options, callback) {
  if (!options)
    return callback(new Error('must provide options'));
  if (!xml)
    return callback(Error('must provide XML to encrypt'));
  if (!options.key)
    return callback(new Error('key option is mandatory and you should provide a valid RSA private key'));
    
  var doc = new xmldom.DOMParser().parseFromString(xml);

  var symmetricKey = decryptKeyInfo(doc, options);
  var encryptionMethod = xpath.select("/*[local-name(.)='EncryptedData']/*[local-name(.)='EncryptionMethod']", doc)[0];
  var encryptionAlgorithm = encryptionMethod.getAttribute('Algorithm');

  var decipher, decrypted;
  var encryptedContent = xpath.select("/*[local-name(.)='EncryptedData']/*[local-name(.)='CipherData']/*[local-name(.)='CipherValue']", doc)[0];
  var encrypted = new Buffer(encryptedContent.textContent, 'base64');

  switch (encryptionAlgorithm) {
    case 'http://www.w3.org/2001/04/xmlenc#aes128-cbc':
      decipher = crypto.createDecipheriv('aes-128-cbc', symmetricKey, encrypted.slice(0, 16));
      if (typeof options.autopadding !== 'undefined') {
        decipher.setAutoPadding(options.autopadding);
      }
      decrypted = decipher.update(encrypted.slice(16), null, 'binary') + decipher.final();
      
      // HACK: padding is not working as expected, 
      // so this is a hack to remove characters which should not be there
      // since the decrypted content will be xml, we just remove chars after >
      if (decrypted.lastIndexOf('>') > 0) {
        decrypted = decrypted.substr(0, decrypted.lastIndexOf('>') + 1);
      }

      break;
    case 'http://www.w3.org/2001/04/xmlenc#aes256-cbc':
      decipher = crypto.createDecipheriv('aes-256-cbc', symmetricKey, encrypted.slice(0, 16)); 
      decrypted = decipher.update(encrypted.slice(16), null, 'binary') + decipher.final();
      break;

    case 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc':
      decipher = crypto.createDecipheriv('des-ede3-cbc', symmetricKey, encrypted.slice(0,8)); 
      decrypted = decipher.update(encrypted.slice(8), null, 'binary') + decipher.final();
      break;
    default:
      return callback(new Error('encryption algorithm ' + encryptionAlgorithm + ' not supported'));
  }
  
  callback(null, decrypted);
}

function decryptKeyInfo(doc, options) {
  if (typeof doc === 'string') doc = new xmldom.DOMParser().parseFromString(doc);

  var keyInfo = xpath.select("//*[local-name(.)='KeyInfo' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']", doc)[0];
  var keyEncryptionMethod = xpath.select("//*[local-name(.)='KeyInfo']/*[local-name(.)='EncryptedKey']/*[local-name(.)='EncryptionMethod']", doc)[0];
  var keyEncryptionAlgorighm = keyEncryptionMethod.getAttribute('Algorithm');
  var encryptedKey = xpath.select("//*[local-name(.)='CipherValue']", keyInfo)[0];

  switch (keyEncryptionAlgorighm) {
    case 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p':      
      return decryptKeyInfoWithScheme(encryptedKey, options, 'RSA-OAEP')
    case 'http://www.w3.org/2001/04/xmlenc#rsa-1_5':      
      return decryptKeyInfoWithScheme(encryptedKey, options, 'RSAES-PKCS1-V1_5')    
    default:
      throw new Error('key encryption algorithm ' + keyEncryptionAlgorighm + ' not supported');
  }
}

function decryptKeyInfoWithScheme(encryptedKey, options, scheme) {
  var key = new Buffer(encryptedKey.textContent, 'base64').toString('binary');
  var private_key = pki.privateKeyFromPem(options.key);
  var decrypted = private_key.decrypt(key, scheme);
  return new Buffer(decrypted, 'binary');
}

function encryptWithAlgorithm(algorithm, symmetricKey, ivLength, content, encoding, callback) {
  // create a random iv for algorithm
  crypto.randomBytes(ivLength, function(err, iv) {
    if (err) return callback(err);
    
    var cipher = crypto.createCipheriv(algorithm, symmetricKey, iv); 
    // encrypted content
    var encrypted = cipher.update(content, encoding, 'binary') + cipher.final('binary');
    return callback(null, Buffer.concat([iv, new Buffer(encrypted, 'binary')]));
  });
}

exports = module.exports = {
  decrypt: decrypt,
  encrypt: encrypt,
  encryptKeyInfo: encryptKeyInfo,
  decryptKeyInfo: decryptKeyInfo
};