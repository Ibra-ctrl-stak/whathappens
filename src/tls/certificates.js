// Signatures in a recorded TLS 1.3 handshake:
// - the certificate chain: each certificate signed by the next, the last by a root Node trusts;
// - CertificateVerify (RFC 8446 §4.4.3): the server's signature over the transcript hash.
import { X509Certificate, createHash, verify, constants } from 'node:crypto';
import { rootCertificates } from 'node:tls';
import { parseHandshake } from './handshake-fields.js';
import { find } from '../fields.js';

const CERTIFICATE = 11;
const CERTIFICATE_VERIFY = 15;
const U24 = 3;
const U16 = 2;

let trustedRoots = null;
const roots = () => {
  trustedRoots ??= rootCertificates.map((pem) => new X509Certificate(pem));
  return trustedRoots;
};

const signedBy = (cert, issuer) => {
  try {
    return cert.verify(issuer.publicKey);
  } catch {
    return false; // e.g. key type the signature cannot be checked with
  }
};

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

const SCHEMES = Object.freeze({
  0x0403: { hash: 'sha256' }, 0x0503: { hash: 'sha384' }, 0x0603: { hash: 'sha512' },
  0x0804: { hash: 'sha256', pss: 32 }, 0x0805: { hash: 'sha384', pss: 48 }, 0x0806: { hash: 'sha512', pss: 64 },
  0x0807: { hash: null }, 0x0808: { hash: null },
});
const CONTEXT = Buffer.concat([Buffer.alloc(64, 0x20), Buffer.from('TLS 1.3, server CertificateVerify', 'ascii'), Buffer.from([0])]);

const messageBytes = (side, m) => side.handshake.subarray(m.offset, m.offset + m.length);

/** decrypted: result of decryptSession. True if the server's CertificateVerify signature holds. */
export function verifyCertificateVerify({ suite, client, server }) {
  const cvIndex = server.messages.findIndex((m) => m.type === CERTIFICATE_VERIFY);
  if (cvIndex < 0) throw new Error('no CertificateVerify in this handshake');
  // Transcript up to (not including) CertificateVerify: ClientHello, ServerHello, EE, Certificate.
  const transcript = Buffer.concat([messageBytes(client, client.messages[0]), ...server.messages.slice(0, cvIndex).map((m) => messageBytes(server, m))]);

  const cv = parseHandshake(server.handshake, server.messages[cvIndex]);
  const scheme = SCHEMES[find(cv, 'algorithm').value];
  if (!scheme) throw new Error(`signature scheme 0x${find(cv, 'algorithm').value.toString(16)} is not supported yet`);
  const sigField = find(cv, 'signature');
  const signature = server.handshake.subarray(sigField.offset + U16, sigField.offset + sigField.length);

  const certTree = parseHandshake(server.handshake, server.messages.find((m) => m.type === CERTIFICATE));
  const leafField = find(certTree, 'cert_data');
  const leaf = new X509Certificate(server.handshake.subarray(leafField.offset + U24, leafField.offset + leafField.length));

  const signed = Buffer.concat([CONTEXT, createHash(suite.hash).update(transcript).digest()]);
  const key = scheme.pss
    ? { key: leaf.publicKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: scheme.pss }
    : { key: leaf.publicKey, dsaEncoding: 'der' };
  return verify(scheme.hash, signed, key, signature);
}
