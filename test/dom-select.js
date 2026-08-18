var assert = require('assert');
var crypto = require('crypto');
var fs = require('fs');
var xmldom = require('@xmldom/xmldom');
var xpath = require('xpath');
var dom = require('../lib/dom-select');
var oaep = require('../lib/oaep');
var xmlenc = require('../lib/xmlenc');

var XENC = 'http://www.w3.org/2001/04/xmlenc#';
var DSIG = 'http://www.w3.org/2000/09/xmldsig#';
var SHA256 = XENC + 'sha256';
var SHA512 = XENC + 'sha512';
var MGF1P = XENC + 'rsa-oaep-mgf1p';

function parse(xml) {
  return new xmldom.DOMParser().parseFromString(xml);
}

// An EncryptedKey wrapping ct, optionally declaring an OAEP DigestMethod.
function encryptedKey(id, digestUri, ct) {
  return '<e:EncryptedKey' + (id ? ' Id="' + id + '"' : '') + '>' +
    '<e:EncryptionMethod Algorithm="' + MGF1P + '">' +
    (digestUri ? '<DigestMethod Algorithm="' + digestUri + '" />' : '') +
    '</e:EncryptionMethod>' +
    '<e:CipherData><e:CipherValue>' + ct.toString('base64') + '</e:CipherValue></e:CipherData>' +
    '</e:EncryptedKey>';
}

// EncryptedData whose KeyInfo points at an out-of-line EncryptedKey by Id.
function retrievalDoc(targetId, keys) {
  return '<root xmlns:e="' + XENC + '">' +
    '<e:EncryptedData><e:KeyInfo><e:RetrievalMethod URI="#' + targetId + '"/></e:KeyInfo></e:EncryptedData>' +
    keys.join('') + '</root>';
}

describe('dom-select', function () {
  describe('scoping', function () {
    it('confines byPath to the subtree of the root it is given', function () {
      // The property XPath's "//" does not have: passing a context node
      // actually restricts the search.
      var doc = parse(
        '<root>' +
          '<a><target>OUTSIDE</target></a>' +
          '<b><target>INSIDE</target></b>' +
        '</root>');
      var b = dom.descendant(doc, 'b');

      assert.equal(dom.byPath(b, ['target']).textContent, 'INSIDE');
      assert.equal(dom.descendant(b, 'target').textContent, 'INSIDE');
      // Contrast: the XPath this replaced ignored the context node entirely.
      assert.equal(xpath.select("//*[local-name(.)='target']", b)[0].textContent, 'OUTSIDE');
    });

    it('returns children only, never deeper descendants', function () {
      var doc = parse('<root><wrap><DigestMethod Algorithm="deep"/></wrap></root>');
      var root = doc.documentElement;

      assert.equal(dom.child(root, 'DigestMethod'), undefined);
      assert.equal(dom.descendant(root, 'DigestMethod').getAttribute('Algorithm'), 'deep');
    });

    it('requires each step of a path to be a parent-child link', function () {
      // 'a/c' must not match a c that sits under a/b.
      var doc = parse('<root><a><b><c>NESTED</c></b></a></root>');
      assert.equal(dom.byPath(doc, ['a', 'c']), undefined);
      assert.equal(dom.byPath(doc, ['a', 'b', 'c']).textContent, 'NESTED');
    });

    it('matches in document order', function () {
      var doc = parse('<root><a><x>FIRST</x></a><a><x>SECOND</x></a></root>');
      assert.equal(dom.byPath(doc, ['a', 'x']).textContent, 'FIRST');
      assert.equal(dom.descendant(doc, 'x').textContent, 'FIRST');
    });

    it('does not climb above the scope to satisfy an earlier path step', function () {
      // Scope is 'a'. The path 'x/a/target' matches by name walking parentNode
      // up from target -- but that chain reaches x, which sits outside a's
      // subtree. Matching it would let a path escape the scope it was given.
      var doc = parse('<root><x><a><target>LEAKED</target></a></x></root>');
      var a = dom.descendant(doc, 'a');
      assert.equal(dom.byPath(a, ['x', 'a', 'target']), undefined);
      // Every step is in scope when anchored where the chain actually lives.
      assert.equal(dom.byPath(doc, ['x', 'a', 'target']).textContent, 'LEAKED');
      assert.equal(dom.byPath(a, ['target']).textContent, 'LEAKED');
    });

    it('only ever returns element nodes', function () {
      // Non-element nodes report localName === null, so a name match cannot
      // select them; the nodeType guard is belt-and-braces over that.
      var doc = parse('<root><!--CipherValue--><a>text</a><?CipherValue x?></root>');
      var el = dom.descendant(doc, 'a');
      assert.equal(el.nodeType, 1);
      assert.equal(el.textContent, 'text');
      assert.equal(dom.descendant(doc, '#comment'), undefined);
      assert.equal(dom.children(doc.documentElement, null).length, 0);
    });

    it('filters child() on namespace, not just descendant()', function () {
      var doc = parse(
        '<root xmlns:e="' + XENC + '" xmlns:d="' + DSIG + '">' +
          '<e:DigestMethod>WRONG-NS</e:DigestMethod>' +
          '<d:DigestMethod>RIGHT-NS</d:DigestMethod>' +
        '</root>');
      var root = doc.documentElement;
      assert.equal(dom.child(root, 'DigestMethod', DSIG).textContent, 'RIGHT-NS');
      assert.equal(dom.child(root, 'DigestMethod', XENC).textContent, 'WRONG-NS');
      assert.equal(dom.child(root, 'DigestMethod', 'urn:absent'), undefined);
      assert.equal(dom.children(root, 'DigestMethod', DSIG).length, 1);
      assert.equal(dom.children(root, 'DigestMethod').length, 2);
    });

    it('filters on namespace when one is given, and ignores prefix', function () {
      var doc = parse(
        '<root xmlns:e="' + XENC + '" xmlns:d="' + DSIG + '">' +
          '<e:KeyInfo>WRONG-NS</e:KeyInfo>' +
          '<d:KeyInfo>RIGHT-NS</d:KeyInfo>' +
        '</root>');
      assert.equal(dom.descendant(doc, 'KeyInfo', DSIG).textContent, 'RIGHT-NS');
      assert.equal(dom.descendant(doc, 'KeyInfo', XENC).textContent, 'WRONG-NS');
      // Without a namespace argument, name alone decides.
      assert.equal(dom.descendant(doc, 'KeyInfo').textContent, 'WRONG-NS');
    });
  });

  describe('elementById', function () {
    it('finds the element carrying the Id', function () {
      var doc = parse(
        '<root xmlns:e="' + XENC + '">' +
          '<e:EncryptedKey Id="a">A</e:EncryptedKey>' +
          '<e:EncryptedKey Id="b">B</e:EncryptedKey>' +
        '</root>');
      assert.equal(dom.elementById(doc, 'EncryptedKey', 'b').textContent, 'B');
      assert.equal(dom.elementById(doc, 'EncryptedKey', 'nope'), undefined);
    });

    it('requires the element name to match, not the Id alone', function () {
      // An Id is only unique within a document, not per element type, so
      // resolving on Id alone lets an unrelated element answer for an
      // EncryptedKey.
      var doc = parse(
        '<root xmlns:e="' + XENC + '">' +
          '<e:CipherValue Id="k1">DECOY</e:CipherValue>' +
          '<e:EncryptedKey Id="k2">REAL</e:EncryptedKey>' +
        '</root>');
      assert.equal(dom.elementById(doc, 'EncryptedKey', 'k1'), undefined);
      assert.equal(dom.elementById(doc, 'EncryptedKey', 'k2').textContent, 'REAL');
    });

    it('treats an Id as an opaque value, not as expression syntax', function () {
      // The XPath this replaced built its predicate by string concatenation, so
      // an Id containing quotes changed the expression's meaning rather than
      // being compared as a value.
      var quoted = "x' or '1'='1";
      var doc = parse(
        '<root xmlns:e="' + XENC + '">' +
          '<e:EncryptedKey Id="first">FIRST</e:EncryptedKey>' +
          '<e:EncryptedKey Id="second">SECOND</e:EncryptedKey>' +
        '</root>');

      // No element carries that Id, so nothing resolves.
      assert.equal(dom.elementById(doc, 'EncryptedKey', quoted), undefined);

      // Contrast: concatenated into an expression, the same value made the
      // predicate true for every element and [0] returned an arbitrary one.
      var expr = "//*[local-name(.)='EncryptedKey' and @Id='" + quoted + "']";
      var matched = xpath.select(expr, doc);
      assert(matched.length > 1, 'a concatenated Id changes the expression');
      assert(matched.indexOf(dom.elementById(doc, 'EncryptedKey', 'first')) >= 0);
    });

    it('refuses a duplicated Id instead of silently picking one', function () {
      // Duplicate Id values are invalid XML. Resolving to the first match makes
      // the choice depend on document order, so ambiguity is refused instead.
      var doc = parse(
        '<root xmlns:e="' + XENC + '">' +
          '<e:EncryptedKey Id="dup">FIRST</e:EncryptedKey>' +
          '<e:EncryptedKey Id="dup">SECOND</e:EncryptedKey>' +
        '</root>');
      assert.throws(function () {
        dom.elementById(doc, 'EncryptedKey', 'dup');
      }, /share Id dup/);
    });
  });
});

describe('decryptKeyInfo element resolution', function () {
  var pub = fs.readFileSync(__dirname + '/test-auth0_rsa.pub');
  var key = fs.readFileSync(__dirname + '/test-auth0.key');

  // All fixtures use rsa-oaep-mgf1p, which fixes MGF1 to SHA-1 (XML-Enc 1.1
  // 5.5.2) independently of the OAEP DigestMethod. crypto.publicEncrypt cannot
  // set MGF1 apart from oaepHash, so wrap through the same OAEP shim the decrypt
  // path uses to produce ciphertext with oaepHash=DigestMethod and MGF1-SHA1.
  function wrap(symmetricKey, oaepHash) {
    return oaep.publicEncryptOaep(pub, symmetricKey, {
      oaepHash: oaepHash,
      mgf1Hash: 'sha1'
    });
  }

  it('pairs DigestMethod with the EncryptedKey actually in use', function () {
    // Two EncryptedKeys under one KeyInfo. The one in use declares no digest
    // (so sha1); the other declares sha512. A document-wide DigestMethod lookup
    // returns the sha512 belonging to the second, and decryption fails.
    var inUse = Buffer.alloc(32, 0x11);
    var other = Buffer.alloc(32, 0x22);
    var xml =
      '<e:EncryptedData xmlns:e="' + XENC + '"><KeyInfo xmlns="' + DSIG + '">' +
        encryptedKey(null, null, wrap(inUse, 'sha1')) +
        encryptedKey(null, SHA512, wrap(other, 'sha512')) +
      '</KeyInfo></e:EncryptedData>';

    var recovered = xmlenc.decryptKeyInfo(xml, { key: key });
    assert.equal(Buffer.compare(Buffer.from(recovered), inUse), 0);

    // Contrast: the document-wide lookup returns a digest from a different key.
    var doc = parse(xml);
    var em = dom.byPath(doc, ['KeyInfo', 'EncryptedKey', 'EncryptionMethod']);
    var strayDigest = xpath.select(
      "//*[local-name(.)='KeyInfo']/*[local-name(.)='EncryptedKey']/*[local-name(.)='EncryptionMethod']/*[local-name(.)='DigestMethod']",
      doc)[0];
    assert.equal(strayDigest.getAttribute('Algorithm'), SHA512);
    assert.notEqual(strayDigest.parentNode, em, 'stray digest belongs to a different EncryptionMethod');
  });

  it('takes the wrapped key from the EncryptedKey, not the first CipherValue in the document', function () {
    // EncryptedData's own CipherData precedes KeyInfo. A document-wide
    // CipherValue lookup returns the content ciphertext as the wrapped key.
    var symmetricKey = Buffer.alloc(32, 0x33);
    var xml =
      '<e:EncryptedData xmlns:e="' + XENC + '">' +
        '<e:CipherData><e:CipherValue>Q09OVEVOVA==</e:CipherValue></e:CipherData>' +
        '<KeyInfo xmlns="' + DSIG + '">' + encryptedKey(null, SHA256, wrap(symmetricKey, 'sha256')) + '</KeyInfo>' +
      '</e:EncryptedData>';

    var recovered = xmlenc.decryptKeyInfo(xml, { key: key });
    assert.equal(Buffer.compare(Buffer.from(recovered), symmetricKey), 0);

    // Contrast: unscoped, the content ciphertext comes back first.
    var doc = parse(xml);
    var keyInfo = dom.descendant(doc, 'KeyInfo', DSIG);
    assert.equal(xpath.select("//*[local-name(.)='CipherValue']", keyInfo)[0].textContent, 'Q09OVEVOVA==');
  });

  describe('RetrievalMethod', function () {
    it('resolves the referenced key when it is not the first in the document', function () {
      var first = Buffer.alloc(32, 0x44);
      var target = Buffer.alloc(32, 0x55);
      var xml = retrievalDoc('ek2', [
        encryptedKey('ek1', null, wrap(first, 'sha1')),
        encryptedKey('ek2', SHA256, wrap(target, 'sha256'))
      ]);
      var recovered = xmlenc.decryptKeyInfo(xml, { key: key });
      assert.equal(Buffer.compare(Buffer.from(recovered), target), 0);
    });

    it('resolves the referenced key when a decoy follows it', function () {
      var target = Buffer.alloc(32, 0x66);
      var decoy = Buffer.alloc(32, 0x77);
      var xml = retrievalDoc('ek1', [
        encryptedKey('ek1', SHA512, wrap(target, 'sha512')),
        encryptedKey('ek2', SHA256, wrap(decoy, 'sha256'))
      ]);
      var recovered = xmlenc.decryptKeyInfo(xml, { key: key });
      assert.equal(Buffer.compare(Buffer.from(recovered), target), 0);
    });

    it('accepts a well-formed fragment reference', function () {
      // Pins the guard's accept side, so a change that rejects everything
      // cannot pass by making the rejection test below trivially true.
      var symmetricKey = Buffer.alloc(32, 0xDD);
      var xml = retrievalDoc('ek1', [encryptedKey('ek1', SHA256, wrap(symmetricKey, 'sha256'))]);
      var recovered = xmlenc.decryptKeyInfo(xml, { key: key });
      assert.equal(Buffer.compare(Buffer.from(recovered), symmetricKey), 0);
    });

    it('rejects a URI that is not a same-document reference', function () {
      // substring(1) chops the first character whatever it is, so without an
      // explicit '#' check "/ek1" and "Xek1" both resolve to Id "ek1" -- a
      // non-fragment URI treated as a local one.
      ['/ek1', 'Xek1', 'ek1', 'https://example.org/keys#ek1', '#', ''].forEach(function (uri) {
        var xml = '<root xmlns:e="' + XENC + '">' +
          '<e:EncryptedData><e:KeyInfo><e:RetrievalMethod URI="' + uri + '"/></e:KeyInfo></e:EncryptedData>' +
          encryptedKey('ek1', null, wrap(Buffer.alloc(32, 0x88), 'sha1')) + '</root>';
        assert.throws(function () {
          xmlenc.decryptKeyInfo(xml, { key: key });
        }, /same-document reference|cant find encryption algorithm/, 'URI ' + JSON.stringify(uri) + ' must be refused');
      });
    });

    it('refuses a reference that resolves to more than one EncryptedKey', function () {
      var xml = retrievalDoc('dup', [
        encryptedKey('dup', null, wrap(Buffer.alloc(32, 0x99), 'sha1')),
        encryptedKey('dup', SHA256, wrap(Buffer.alloc(32, 0xAA), 'sha256'))
      ]);
      assert.throws(function () {
        xmlenc.decryptKeyInfo(xml, { key: key });
      }, /share Id dup/);
    });

    it('does not let an Id change the meaning of resolution', function () {
      var xml = '<root xmlns:e="' + XENC + '">' +
        '<e:EncryptedData><e:KeyInfo><e:RetrievalMethod URI="#x&apos; or &apos;1&apos;=&apos;1"/></e:KeyInfo></e:EncryptedData>' +
        encryptedKey('first', null, wrap(Buffer.alloc(32, 0xBB), 'sha1')) +
        encryptedKey('second', SHA256, wrap(Buffer.alloc(32, 0xCC), 'sha256')) + '</root>';
      // No element has that Id, so resolution finds nothing rather than matching all.
      assert.throws(function () {
        xmlenc.decryptKeyInfo(xml, { key: key });
      }, /cant find encryption algorithm/);
    });
  });

  it('reports a missing CipherValue rather than throwing on a null read', function () {
    var xml =
      '<e:EncryptedData xmlns:e="' + XENC + '"><KeyInfo xmlns="' + DSIG + '">' +
        '<e:EncryptedKey><e:EncryptionMethod Algorithm="' + MGF1P + '"/></e:EncryptedKey>' +
      '</KeyInfo></e:EncryptedData>';
    assert.throws(function () {
      xmlenc.decryptKeyInfo(xml, { key: key });
    }, /cant find encrypted key/);
  });
});
