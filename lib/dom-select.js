// Explicit DOM traversal for locating XML-Enc elements.
//
// This module deliberately does not use XPath. Two properties of the previous
// XPath lookups made this key-selection path fragile:
//
//   1. Expressions were built from document content. The RetrievalMethod URI
//      was spliced into a predicate, so a URI of "#x' or '1'='1" closed the
//      quote and changed what the expression meant, matching every
//      EncryptedKey in the document instead of comparing an Id. Here a
//      document value is only ever compared, never concatenated into
//      anything that gets parsed.
//
//   2. Scope was a string, not a node. "//" is descendant-or-self over the
//      whole document regardless of the context node handed to select(), so
//      lookups that read as relative were silently document-wide, and could
//      pair one EncryptedKey's ciphertext with a different one's DigestMethod.
//      Here scope is the root argument, and it is enforced by the walk itself.
//
// Only element nodes are candidates; text, comments and PIs never match.

const ELEMENT_NODE = 1;

// Element children of node, in document order.
function children(node, localName, namespaceUri) {
  const out = [];
  if (!node) return out;
  for (let n = node.firstChild; n; n = n.nextSibling) {
    if (n.nodeType !== ELEMENT_NODE) continue;
    if (n.localName !== localName) continue;
    if (namespaceUri !== undefined && n.namespaceURI !== namespaceUri) continue;
    out.push(n);
  }
  return out;
}

function child(node, localName, namespaceUri) {
  return children(node, localName, namespaceUri)[0];
}

// Pre-order depth-first walk of root's subtree, root included. Pre-order is
// document order, so the first element visited that satisfies a predicate is
// the same element XPath's [0] would have returned.
function walk(root, visit) {
  if (!root) return undefined;
  const start = root.nodeType === ELEMENT_NODE ? root : root.documentElement;
  if (!start) return undefined;
  const stack = [start];
  while (stack.length) {
    const node = stack.pop();
    const found = visit(node);
    if (found !== undefined) return found;
    // Push in reverse so the first child is visited first.
    const kids = [];
    for (let n = node.firstChild; n; n = n.nextSibling) {
      if (n.nodeType === ELEMENT_NODE) kids.push(n);
    }
    for (let i = kids.length - 1; i >= 0; i--) stack.push(kids[i]);
  }
  return undefined;
}

// True when node is the tail of localNames, each earlier name being its
// parent, and the head of the chain lies within root's subtree. This is the
// node-wise reading of "A/B/C": C's parent is B, B's parent is A, A anywhere
// under root.
function matchesPath(node, localNames, root) {
  let current = node;
  for (let i = localNames.length - 1; i >= 0; i--) {
    if (!current || current.nodeType !== ELEMENT_NODE) return false;
    if (current.localName !== localNames[i]) return false;
    if (i > 0) current = current.parentNode;
  }
  // Confirm the head of the chain is inside the requested scope.
  const scope = root.nodeType === ELEMENT_NODE ? root : root.documentElement;
  for (let n = current; n; n = n.parentNode) {
    if (n === scope) return true;
  }
  return false;
}

// First element in root's subtree matching the child-step path, e.g.
// byPath(doc, ['EncryptedData', 'CipherData', 'CipherValue']).
function byPath(root, localNames) {
  return walk(root, function (node) {
    return matchesPath(node, localNames, root) ? node : undefined;
  });
}

// First descendant-or-self of root with this name, optionally namespace-qualified.
function descendant(root, localName, namespaceUri) {
  return walk(root, function (node) {
    if (node.localName !== localName) return undefined;
    if (namespaceUri !== undefined && node.namespaceURI !== namespaceUri) return undefined;
    return node;
  });
}

// The single element named localName carrying Id === id.
//
// Duplicate Id values are invalid XML. Resolving to the first of several makes
// the result depend on document order, so ambiguity is refused rather than
// resolved.
function elementById(root, localName, id) {
  const matches = [];
  walk(root, function (node) {
    if (node.localName === localName && node.getAttribute('Id') === id) matches.push(node);
    return undefined; // visit every node
  });
  if (matches.length > 1) {
    throw new Error('multiple ' + localName + ' elements share Id ' + id);
  }
  return matches[0];
}

module.exports = { children, child, byPath, descendant, elementById };
