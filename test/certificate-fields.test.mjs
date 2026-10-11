// Certificate and CertificateVerify: byte-exact fields, X509Certificate details checked against
// Wireshark, the chain's signatures, and the server's signature over the handshake transcript.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { loadSession } from '../src/session.js';
import { decryptSession } from '../src/tls/decrypt.js';
import { parseHandshake } from '../src/tls/handshake-fields.js';
import { verifyChain, verifyCertificateVerify } from '../src/tls/certificates.js';
import { find, findAll } from '../src/fields.js';

const json = (name) => JSON.parse(readFileSync(new URL(`./fixtures/github-robots/${name}`, import.meta.url), 'utf8'));
const expected = json('expected.json').tls;
const decrypted = decryptSession(loadSession(json('session.json')).tls);
const { server } = decrypted;
const CERTIFICATE = 11;
const CERTIFICATE_VERIFY = 15;

const treeOf = (type) => parseHandshake(server.handshake, server.messages.find((m) => m.type === type));
const certificate = treeOf(CERTIFICATE);
const entries = findAll(certificate, 'certificate_entry');
const certData = entries.map((e) => find(e, 'cert_data'));
const x509s = certData.map((d) => d.x509);
const tsharkTime = (s) => new Date(s.replace(' (UTC)', 'Z').replace(' ', 'T')).toISOString();
const normSerial = (s) => s.replace(/^(00)+/, '').toLowerCase();

test('Certificate: one entry per certificate, DER bytes identical to what Wireshark saw', () => {
  assert.equal(entries.length, expected.certificates.length);
  certData.forEach((d, i) => {
    const der = server.handshake.subarray(d.offset + 3, d.offset + d.length); // after the u24 length
    assert.equal(der.length, expected.certificates[i].length);
    assert.equal(createHash('sha256').update(der).digest('hex'), expected.certificates[i].derSha256);
  });
});

test('Certificate: X509 serial numbers and validity match Wireshark', () => {
  x509s.forEach((x, i) => {
    assert.equal(normSerial(x.serialNumber), expected.certificates[i].serial);
    assert.equal(x.validFrom, tsharkTime(expected.certificates[i].notBefore));
    assert.equal(x.validTo, tsharkTime(expected.certificates[i].notAfter));
  });
});

test('Certificate: subject, issuer and SAN of the leaf; each issuer is the next subject', () => {
  const [leaf] = x509s;
  assert.match(leaf.subject, /CN=github\.com/);
  assert.deepEqual(leaf.dnsNames, expected.leafDnsNames);
  for (let i = 0; i + 1 < x509s.length; i += 1) assert.equal(x509s[i].issuer, x509s[i + 1].subject);
  assert.equal(certData[0].value, leaf.subject.split('\n').find((l) => l.startsWith('CN=')));
});

test('chain: every link is signed by the next certificate, the last by a trusted root, host matches', () => {
  const recordedAt = new Date(json('session.json').startedAt); // judged then, so this test does not rot
  const result = verifyChain(certData.map((d) => server.handshake.subarray(d.offset + 3, d.offset + d.length)), 'github.com', recordedAt);
  assert.ok(result.links.length === entries.length - 1 && result.links.every((l) => l.issued && l.signatureValid), JSON.stringify(result.links));
  assert.equal(result.root.found, true);
  assert.equal(result.root.signatureValid, true);
  assert.equal(result.hostnameMatches, true);
  assert.equal(result.valid, true);
});

test('chain: certificates in the wrong order do not verify', () => {
  const ders = certData.map((d) => server.handshake.subarray(d.offset + 3, d.offset + d.length));
  const result = verifyChain([ders[1], ders[0], ...ders.slice(2)], 'github.com');
  assert.equal(result.valid, false);
  assert.ok(result.links.some((l) => !l.signatureValid));
});

test('CertificateVerify: scheme as in Wireshark, signature field covers its bytes', () => {
  const cv = treeOf(CERTIFICATE_VERIFY);
  assert.equal(find(cv, 'algorithm').value, expected.certificateVerifyScheme);
  assert.equal(find(cv, 'algorithm').label, 'ecdsa_secp256r1_sha256');
  const sig = find(cv, 'signature');
  assert.equal(sig.offset + sig.length, cv.offset + cv.length);
});

test('CertificateVerify: the server\'s signature over our reconstructed transcript is valid', () => {
  assert.equal(verifyCertificateVerify(decrypted), true);
});

test('CertificateVerify: one changed transcript byte breaks the signature', () => {
  const handshake = Buffer.from(decrypted.client.handshake);
  handshake[10] ^= 0x01; // inside ClientHello.random
  assert.equal(verifyCertificateVerify({ ...decrypted, client: { ...decrypted.client, handshake } }), false);
});

test('chain: validity is judged at the moment the session was recorded, not today', () => {
  const ders = certData.map((d) => server.handshake.subarray(d.offset + 3, d.offset + d.length));
  const recordedAt = new Date(json('session.json').startedAt);
  const then = verifyChain(ders, 'github.com', recordedAt);
  assert.deepEqual(then.certificates.map((c) => c.inValidityPeriod), [true, true, true]);
  const afterLeafExpiry = new Date(Date.parse(x509s[0].validTo) + 1000);
  const later = verifyChain(ders, 'github.com', afterLeafExpiry);
  assert.deepEqual(later.certificates.map((c) => c.inValidityPeriod), [false, true, true]);
  assert.equal(later.valid, false);
});
