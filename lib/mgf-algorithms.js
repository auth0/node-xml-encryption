// MGF URI ↔ short-name maps. XML-Enc 1.1 5.5.2.
//
// MGF_CANONICAL is the normative list, and the only source for what we emit.
// MGF_LEGACY_ALIASES is accepted on decrypt only: the xmlenc#MGF1withSHA1
// spelling appears in Example 33 of that same section and implementations
// copied it, but it is not in the normative list and must never be emitted.
// Keeping the two separate means reordering either literal cannot change what
// we emit.
const MGF_CANONICAL = Object.assign(Object.create(null), {
  'http://www.w3.org/2009/xmlenc11#mgf1sha1': 'sha1',
  'http://www.w3.org/2009/xmlenc11#mgf1sha224': 'sha224',
  'http://www.w3.org/2009/xmlenc11#mgf1sha256': 'sha256',
  'http://www.w3.org/2009/xmlenc11#mgf1sha384': 'sha384',
  'http://www.w3.org/2009/xmlenc11#mgf1sha512': 'sha512'
});

const MGF_LEGACY_ALIASES = Object.assign(Object.create(null), {
  'http://www.w3.org/2001/04/xmlenc#MGF1withSHA1': 'sha1'
});

// URI → short name, for decrypt. Accepts the legacy alias.
const MGF_ALGORITHMS = Object.assign(Object.create(null), MGF_CANONICAL, MGF_LEGACY_ALIASES);

// Short name → URI, for encrypt. Derived from the canonical map alone, so a
// short name we accept on decrypt is either emittable as a normative URI or
// not emittable at all — never emittable as the legacy alias.
const MGF_URI_FOR_EMIT = Object.create(null);
for (const uri of Object.keys(MGF_CANONICAL)) {
  MGF_URI_FOR_EMIT[MGF_CANONICAL[uri]] = uri;
}

const MGF_SHORT_NAMES = Object.keys(MGF_URI_FOR_EMIT);

module.exports = { MGF_ALGORITHMS, MGF_SHORT_NAMES, MGF_URI_FOR_EMIT };
