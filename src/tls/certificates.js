// Signatures in a recorded TLS 1.3 handshake:
// - the certificate chain: each certificate signed by the next, the last by a root Node trusts;
// - CertificateVerify (RFC 8446 §4.4.3): the server's signature over the transcript hash.
import { X509Certificate, createHash, verify, constants } from 'node:crypto';
import { rootCertificates } from 'node:tls';
import { parseHandshake } from './handshake-fields.js';
import { HANDSHAKE_TYPES, SIGNATURE_SCHEMES } from './names.js';
import { find, findAll } from '../fields.js';

const CLIENT_HELLO = 1;
const SERVER_HELLO = 2;
const HRR_RANDOM = 'cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c'; // RFC 8446 §4.1.3
const CERTIFICATE = 11;
const CERTIFICATE_VERIFY = 15;
const U24 = 3;
const U16 = 2;

let trustedRoots = null;
const roots = () => {
  trustedRoots ??= rootCertificates.map((pem) => new X509Certificate(pem));
  return trustedRoots;
};

/** Three-valued signature check of `cert` with `issuer`'s public key (exported for tests). */
export function signatureStatus(cert, issuer) {
  try {
    return cert.verify(issuer.publicKey)
      ? { status: 'passed', reason: null }
      : { status: 'failed', reason: 'the signature does not verify with the issuer\'s public key' };
  } catch (err) {
    return { status: 'unavailable', reason: `the signature could not be checked: ${err.message}` }; // e.g. unsupported key type
  }
}

const signedBy = (cert, issuer) => signatureStatus(cert, issuer).status === 'passed';

/**
 * ders: certificate DER buffers in the order the server sent them (leaf first).
 * at: the moment validity periods are judged against — for a recording, when it was made.
 */
export function verifyChain(ders, hostname, at = new Date()) {
  const certs = ders.map((der) => new X509Certificate(der));
  const certificates = certs.map((c) => ({
    subject: c.subject,
    inValidityPeriod: c.validFromDate <= at && at <= c.validToDate,
  }));
  const links = certs.slice(0, -1).map((cert, i) => ({
    subject: cert.subject,
    issuer: certs[i + 1].subject,
    issued: cert.checkIssued(certs[i + 1]),
    signatureValid: signedBy(cert, certs[i + 1]),
  }));
  const last = certs.at(-1);
  const candidates = roots().filter((r) => last.checkIssued(r));
  const anchor = candidates.find((r) => signedBy(last, r));
  const root = { found: candidates.length > 0, subject: (anchor ?? candidates[0])?.subject ?? null, signatureValid: Boolean(anchor) };
  const hostnameMatches = certs[0].checkHost(hostname) !== undefined;
  const valid = links.every((l) => l.issued && l.signatureValid) && root.signatureValid && hostnameMatches
    && certificates.every((c) => c.inValidityPeriod);
  return { certificates, links, root, hostnameMatches, valid };
}

// Each scheme also names the key it needs (RFC 8446 §4.2.3): crypto.verify does not enforce it —
// with an EC key it ignores RSA-PSS options and a null digest and checks plain ECDSA instead.
const SCHEMES = Object.freeze({
  0x0403: { hash: 'sha256', key: 'ec', curve: 'prime256v1' },
  0x0503: { hash: 'sha384', key: 'ec', curve: 'secp384r1' },
  0x0603: { hash: 'sha512', key: 'ec', curve: 'secp521r1' },
  0x0804: { hash: 'sha256', pss: 32, key: 'rsa' }, 0x0805: { hash: 'sha384', pss: 48, key: 'rsa' }, 0x0806: { hash: 'sha512', pss: 64, key: 'rsa' },
  0x0807: { hash: null, key: 'ed25519' }, 0x0808: { hash: null, key: 'ed448' },
});

/** Why the certificate's key cannot carry this scheme's signature, or null if it fits. */
function keyMismatch(inputs) {
  const { asymmetricKeyType: type, asymmetricKeyDetails: details = {} } = inputs.leaf.publicKey;
  const { key, curve } = inputs.scheme;
  if (type === key && (!curve || details.namedCurve === curve)) return null;
  const has = details.namedCurve ? `${type} (${details.namedCurve})` : type;
  return `signature scheme ${inputs.schemeName} requires a ${curve ? `${key} (${curve})` : key} key, but the certificate has a ${has} key`;
}
const CONTEXT = Buffer.concat([Buffer.alloc(64, 0x20), Buffer.from('TLS 1.3, server CertificateVerify', 'ascii'), Buffer.from([0])]);

const messageBytes = (side, m) => side.handshake.subarray(m.offset, m.offset + m.length);
const hex4 = (n) => `0x${n.toString(16).padStart(4, '0')}`;

/**
 * Everything CertificateVerify needs from a decrypted session, or { unavailable: reason }.
 * Transcript (RFC 8446 §4.4.1): ClientHello, then the server's messages before CertificateVerify.
 */
function certificateVerifyInputs({ suite, client, server }) {
  const cvIndex = server.messages.findIndex((m) => m.type === CERTIFICATE_VERIFY);
  if (cvIndex < 0) return { unavailable: 'no CertificateVerify message was received and decrypted' };
  if (client.messages[0]?.type !== CLIENT_HELLO) return { unavailable: 'no ClientHello in the recording' };
  // After a HelloRetryRequest the transcript starts with a synthetic message_hash (RFC 8446
  // §4.4.1); checking it as a plain ClientHello transcript would give a false "failed".
  const serverHello = server.messages[0];
  const hrr = (serverHello?.type === SERVER_HELLO && messageBytes(server, serverHello).subarray(6, 38).toString('hex') === HRR_RANDOM)
    || client.messages.filter((m) => m.type === CLIENT_HELLO).length > 1;
  if (hrr) return { unavailable: 'HelloRetryRequest handshakes are not supported by this checker (their transcript starts with message_hash)' };
  const before = server.messages.slice(0, cvIndex);
  const certMessage = before.find((m) => m.type === CERTIFICATE);
  if (!certMessage) return { unavailable: 'no Certificate message before CertificateVerify' };

  const cv = parseHandshake(server.handshake, server.messages[cvIndex]);
  if (cv.problem) return { unavailable: `CertificateVerify does not parse: ${cv.problem}` };
  const algorithm = find(cv, 'algorithm').value;
  const scheme = SCHEMES[algorithm];
  const schemeName = SIGNATURE_SCHEMES[algorithm] ?? 'unknown';
  if (!scheme) return { unavailable: `signature scheme ${hex4(algorithm)} (${schemeName}) is not supported by this checker` };
  const sigField = find(cv, 'signature');
  const signature = server.handshake.subarray(sigField.offset + U16, sigField.offset + sigField.length);

  const certTree = parseHandshake(server.handshake, certMessage);
  const leafField = certTree.problem ? null : find(certTree, 'cert_data');
  if (!leafField) return { unavailable: 'the Certificate message carries no certificate' };
  let leaf;
  try {
    leaf = new X509Certificate(server.handshake.subarray(leafField.offset + U24, leafField.offset + leafField.length));
  } catch (err) {
    return { unavailable: `the server's first certificate does not decode: ${err.message}` };
  }
  const transcriptMessages = [client.messages[0], ...before];
  return {
    scheme, schemeName, signature, leaf, hash: suite.hash,
    transcript: Buffer.concat([messageBytes(client, client.messages[0]), ...before.map((m) => messageBytes(server, m))]),
    transcriptNames: transcriptMessages.map((m) => HANDSHAKE_TYPES[m.type] ?? `handshake ${m.type}`),
  };
}

function runCertificateVerify(inputs) {
  if (keyMismatch(inputs)) return false;
  const signed = Buffer.concat([CONTEXT, createHash(inputs.hash).update(inputs.transcript).digest()]);
  const key = inputs.scheme.pss
    ? { key: inputs.leaf.publicKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: inputs.scheme.pss }
    : { key: inputs.leaf.publicKey, dsaEncoding: 'der' };
  return verify(inputs.scheme.hash, signed, key, inputs.signature);
}

/** decrypted: result of decryptSession. True if the server's CertificateVerify signature holds. */
export function verifyCertificateVerify(decrypted) {
  const inputs = certificateVerifyInputs(decrypted);
  if (inputs.unavailable) throw new Error(inputs.unavailable);
  return runCertificateVerify(inputs);
}

// ---- three-valued results for the viewer: passed / failed / unavailable (with a reason) ---------

const CV_NOT_COVERED = Object.freeze([
  'whether the certificate itself is trusted (see the certificate chain check)',
  'whether the signature scheme was among those offered in ClientHello',
  'the Finished messages',
]);

const CHAIN_NOT_COVERED = Object.freeze([
  'host name match',
  'validity periods (dates)',
  'certificate extensions and constraints (basicConstraints, keyUsage, name constraints)',
  'revocation (OCSP, CRL)',
  'Certificate Transparency',
  'alternative chains other than the one the server sent',
]);

const result = (fields) => ({ reason: null, steps: [], ...fields });

/** CertificateVerify of a decrypted session as a viewer-ready result. Never throws. */
export function certificateVerifyCheck(decrypted) {
  const base = { id: 'certificate-verify', title: 'CertificateVerify signature', notCovered: [...CV_NOT_COVERED] };
  const inputs = certificateVerifyInputs(decrypted);
  if (inputs.unavailable) {
    return result({ ...base, status: 'unavailable', reason: inputs.unavailable, explanation: 'The server\'s signature over the handshake transcript could not be checked.' });
  }
  const explanation = `The server's ${inputs.schemeName} signature over the ${inputs.hash.toUpperCase()} hash of the transcript `
    + `(${inputs.transcriptNames.join(', ')}), checked with the public key of the server's first certificate.`;
  const mismatch = keyMismatch(inputs);
  if (mismatch) return result({ ...base, status: 'failed', explanation, reason: mismatch });
  try {
    return runCertificateVerify(inputs)
      ? result({ ...base, status: 'passed', explanation })
      : result({ ...base, status: 'failed', explanation, reason: 'the signature does not match the transcript hash and the certificate\'s public key' });
  } catch (err) {
    return result({ ...base, status: 'unavailable', explanation, reason: `the signature could not be checked: ${err.message}` });
  }
}

const shortName = (subject) => subject.split('\n').find((l) => l.startsWith('CN=')) ?? subject.replace(/\n/g, ', ');

function chainLinkStep(cert, issuer) {
  const label = `${shortName(cert.subject)} signed by ${shortName(issuer.subject)}`;
  if (!cert.checkIssued(issuer)) return { label, status: 'failed', reason: 'the issuer name does not match the next certificate\'s subject' };
  return { label, ...signatureStatus(cert, issuer) };
}

function rootStep(last) {
  const candidates = roots().filter((r) => last.checkIssued(r));
  if (candidates.length === 0) {
    return { label: `${shortName(last.subject)} signed by a root in Node's built-in root store`, status: 'unavailable',
      reason: `no root in Node's built-in root store has the subject ${JSON.stringify(shortName(last.issuer))}; the link to a trusted root cannot be checked` };
  }
  const steps = candidates.map((r) => ({ label: `${shortName(last.subject)} signed by root ${shortName(r.subject)} (Node's built-in root store)`, ...signatureStatus(last, r) }));
  return steps.find((s) => s.status === 'passed') ?? steps.find((s) => s.status === 'failed') ?? steps[0];
}

/** ders: certificates as sent (leaf first). Signatures of the chain as a viewer-ready result. Never throws. */
export function chainSignatureCheck(ders) {
  const base = {
    id: 'certificate-chain', title: 'Certificate chain signatures', notCovered: [...CHAIN_NOT_COVERED],
    explanation: 'Each certificate\'s signature checked with the public key of the next certificate the server sent '
      + '(issuer name must match), and the last one with a root certificate from Node\'s built-in root store.',
  };
  if (ders.length === 0) return result({ ...base, status: 'unavailable', reason: 'the server sent no certificates' });
  const certs = [];
  for (const [i, der] of ders.entries()) {
    try {
      certs.push(new X509Certificate(der));
    } catch (err) {
      return result({ ...base, status: 'unavailable', reason: `certificate ${i + 1} of ${ders.length} does not decode: ${err.message}` });
    }
  }
  const steps = [...certs.slice(0, -1).map((c, i) => chainLinkStep(c, certs[i + 1])), rootStep(certs.at(-1))];
  const failed = steps.find((s) => s.status === 'failed');
  const unavailable = steps.find((s) => s.status === 'unavailable');
  const status = failed ? 'failed' : unavailable ? 'unavailable' : 'passed';
  return result({ ...base, status, steps, reason: (failed ?? unavailable)?.reason ?? null });
}

/** Both checks for a decrypted session; a broken Certificate message makes the chain unavailable. */
export function handshakeChecks(decrypted) {
  const certMessage = decrypted.server.messages.find((m) => m.type === CERTIFICATE);
  const certTree = certMessage ? parseHandshake(decrypted.server.handshake, certMessage) : null;
  const chain = !certTree
    ? result({ ...chainSignatureCheck([]), reason: 'no Certificate message was received and decrypted' })
    : certTree.problem
      ? result({ ...chainSignatureCheck([]), reason: `the Certificate message does not parse: ${certTree.problem}` })
      : chainSignatureCheck(findAll(certTree, 'cert_data').map((d) => decrypted.server.handshake.subarray(d.offset + U24, d.offset + d.length)));
  return { certificateVerify: certificateVerifyCheck(decrypted), chain };
}
