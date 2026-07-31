// Canonical MGF URI → short-name map. XML-Enc 1.1 5.5.2. The normative list
// uses the xmlenc11#mgf1* URIs; the xmlenc#MGF1withSHA1 spelling is accepted
// on decrypt because Example 33 in that same section uses it and implementations
// copied it.
const MGF_ALGORITHMS = Object.assign(Object.create(null), {
  'http://www.w3.org/2009/xmlenc11#mgf1sha1': 'sha1',
  'http://www.w3.org/2009/xmlenc11#mgf1sha224': 'sha224',
  'http://www.w3.org/2009/xmlenc11#mgf1sha256': 'sha256',
  'http://www.w3.org/2009/xmlenc11#mgf1sha384': 'sha384',
  'http://www.w3.org/2009/xmlenc11#mgf1sha512': 'sha512',
  'http://www.w3.org/2001/04/xmlenc#MGF1withSHA1': 'sha1'
});

const MGF_SHORT_NAMES = Object.values(MGF_ALGORITHMS);

// Derive short-name → URI map for emit, excluding the legacy alias.
// xmlenc11#mgf1sha1 must win over xmlenc#MGF1withSHA1 for sha1.
const MGF_URI_FOR_EMIT = Object.assign(Object.create(null), {});
for (const [uri, shortName] of Object.entries(MGF_ALGORITHMS)) {
  // Only set if not already present (first occurrence wins).
  // The xmlenc11#mgf1sha1 entry comes before the legacy entry, so it wins.
  if (!MGF_URI_FOR_EMIT[shortName]) {
    MGF_URI_FOR_EMIT[shortName] = uri;
  }
}

module.exports = { MGF_ALGORITHMS, MGF_SHORT_NAMES, MGF_URI_FOR_EMIT };
