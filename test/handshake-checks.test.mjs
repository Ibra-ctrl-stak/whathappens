// Our own handshake checks, three-valued: passed / failed / unavailable (with a concrete reason).
// "unavailable" must never be reported as success.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadSession } from '../src/session.js';
import { decryptSession, parseKeylog, trafficKeys, SUITES } from '../src/tls/decrypt.js';
import { parseHandshake } from '../src/tls/handshake-fields.js';
import { certificateVerifyCheck, chainSignatureCheck, handshakeChecks } from '../src/tls/certificates.js';
import { buildTimeline } from '../src/timeline.js';
import { find, findAll } from '../src/fields.js';
import { sealRecord } from './helpers/tls-seal.mjs';
import { editStream, replaceBytes } from './helpers/session-edit.mjs';

const golden = JSON.parse(readFileSync(new URL('./fixtures/github-robots/session.json', import.meta.url), 'utf8'));
const decrypted = decryptSession(loadSession(golden).tls);
const { server } = decrypted;
const CERTIFICATE = 11;
const CERTIFICATE_VERIFY = 15;
const STATUSES = ['passed', 'failed', 'unavailable'];

const treeOf = (type) => parseHandshake(server.handshake, server.messages.find((m) => m.type === type));
const certDataFields = findAll(treeOf(CERTIFICATE), 'cert_data');
const ders = certDataFields.map((d) => Buffer.from(server.handshake.subarray(d.offset + 3, d.offset + d.length)));
const withServerHandshake = (edit) => {
  const handshake = Buffer.from(server.handshake);
  edit(handshake);
  return { ...decrypted, server: { ...server, handshake } };
};
const signatureField = find(treeOf(CERTIFICATE_VERIFY), 'signature');
const algorithmField = find(treeOf(CERTIFICATE_VERIFY), 'algorithm');

test('reference session: CertificateVerify passes, with what was checked spelled out', () => {
  const check = certificateVerifyCheck(decrypted);
  assert.equal(check.status, 'passed');
  assert.equal(check.reason, null);
  assert.match(check.explanation, /ecdsa_secp256r1_sha256/);
  assert.match(check.explanation, /ClientHello, ServerHello, EncryptedExtensions, Certificate/);
  assert.ok(check.notCovered.length > 0);
});

test('reference session: every chain signature passes and the last links to a root in Node\'s store', () => {
  const check = chainSignatureCheck(ders);
  assert.equal(check.status, 'passed');
  assert.equal(check.steps.length, ders.length); // one per sent certificate, the last against the root
  assert.ok(check.steps.every((s) => s.status === 'passed'));
  assert.match(check.steps.at(-1).label, /USERTrust ECC Certification Authority/);
  for (const topic of [/host name/, /validity/, /revocation/, /constraints/]) {
    assert.ok(check.notCovered.some((n) => topic.test(n)), `notCovered mentions ${topic}`);
  }
});

test('a changed CertificateVerify signature fails', () => {
  const tampered = withServerHandshake((h) => { h[signatureField.offset + 2 + 10] ^= 0x01; }); // inside the DER integer r
  const check = certificateVerifyCheck(tampered);
  assert.equal(check.status, 'failed');
  assert.match(check.reason, /does not match/);
});

test('a changed transcript fails the CertificateVerify check', () => {
  const handshake = Buffer.from(decrypted.client.handshake);
  handshake[10] ^= 0x01; // inside ClientHello.random
  assert.equal(certificateVerifyCheck({ ...decrypted, client: { ...decrypted.client, handshake } }).status, 'failed');
});

test('a changed signature inside the leaf certificate fails the chain check at that link', () => {
  const broken = ders.map((d, i) => (i === 0 ? Buffer.from(d) : d));
  broken[0][broken[0].length - 1] ^= 0x01; // last byte of the leaf's signatureValue
  const check = chainSignatureCheck(broken);
  assert.equal(check.status, 'failed');
  assert.deepEqual(check.steps.map((s) => s.status), ['failed', 'passed', 'passed']);
});

test('certificates in the wrong order fail the chain check', () => {
  assert.equal(chainSignatureCheck([ders[1], ders[0], ders[2]]).status, 'failed');
});

test('no CertificateVerify in the recording: unavailable, with the reason', () => {
  const check = certificateVerifyCheck({ ...decrypted, server: { ...server, messages: server.messages.filter((m) => m.type !== CERTIFICATE_VERIFY) } });
  assert.equal(check.status, 'unavailable');
  assert.match(check.reason, /no CertificateVerify/);
});

test('an unsupported signature scheme: unavailable, never passed', () => {
  const check = certificateVerifyCheck(withServerHandshake((h) => h.writeUInt16BE(0x0201, algorithmField.offset)));
  assert.equal(check.status, 'unavailable');
  assert.match(check.reason, /0x0201/);
});

test('a certificate that does not decode: both checks unavailable, the reason names it', () => {
  const corrupt = withServerHandshake((h) => { h[certDataFields[0].offset + 3] ^= 0xff; }); // DER SEQUENCE tag of the leaf
  const checks = handshakeChecks(corrupt);
  assert.equal(checks.certificateVerify.status, 'unavailable');
  assert.match(checks.certificateVerify.reason, /does not decode/);
  assert.equal(checks.chain.status, 'unavailable');
  assert.match(checks.chain.reason, /certificate 1 .*does not decode/);
});

test('a chain whose issuer is not in Node\'s root store: the root link is unavailable, not passed', () => {
  const localhost = readFileSync(new URL('./fixtures/localhost-tls/cert.pem', import.meta.url));
  const check = chainSignatureCheck([localhost]);
  assert.equal(check.status, 'unavailable');
  assert.equal(check.steps.at(-1).status, 'unavailable');
  assert.match(check.steps.at(-1).reason, /Node's built-in root store/);
});

test('every status is one of the three, on every case above', () => {
  for (const check of [certificateVerifyCheck(decrypted), chainSignatureCheck(ders), chainSignatureCheck([])]) {
    assert.ok(STATUSES.includes(check.status));
    for (const s of check.steps ?? []) assert.ok(STATUSES.includes(s.status));
  }
  assert.equal(chainSignatureCheck([]).status, 'unavailable');
});

// ---- on the timeline ------------------------------------------------------------------------

const timeline = buildTimeline(loadSession(golden));
const messageEvent = (t, name) => t.events.find((e) => e.kind === 'handshake-message' && e.dir === 'in' && e.summary === name);

test('timeline: results sit on the Certificate and CertificateVerify events only, without bytes or time of their own', () => {
  const cert = messageEvent(timeline, 'Certificate');
  const cv = messageEvent(timeline, 'CertificateVerify');
  assert.deepEqual(cert.checks.map((c) => [c.id, c.status]), [['certificate-chain', 'passed']]);
  assert.deepEqual(cv.checks.map((c) => [c.id, c.status]), [['certificate-verify', 'passed']]);
  for (const c of [...cert.checks, ...cv.checks]) {
    assert.ok(!('offset' in c) && !('length' in c) && !('at' in c) && !('t' in c));
  }
  assert.ok(timeline.events.filter((e) => e !== cert && e !== cv).every((e) => e.checks === null));
  assert.ok(cert.length > 0 && cv.length > 0, 'the events keep their own bytes');
});

test('timeline: a re-encrypted handshake with a corrupted CertificateVerify signature shows a failed check', () => {
  const hs = server.records.filter((r) => r.epoch === 'handshake');
  const content = Buffer.concat(hs.map((r) => r.content));
  content[signatureField.offset + 2 + 10 - hs[0].handshakeOffset] ^= 0x01;
  const suite = SUITES[decrypted.suite.id];
  const keys = trafficKeys(suite, parseKeylog(golden.tls.keylog).secrets.SERVER_HANDSHAKE_TRAFFIC_SECRET);
  let at = 0;
  const sealed = hs.map((r, seq) => {
    const part = content.subarray(at, at + r.content.length);
    at += r.content.length;
    return sealRecord(suite, keys, seq, 22, part);
  });
  const start = hs[0].offset;
  const end = hs.at(-1).offset + 5 + hs.at(-1).length;
  const t = buildTimeline(loadSession(editStream(golden, 'in', replaceBytes(start, end - start, Buffer.concat(sealed)))));
  const cv = messageEvent(t, 'CertificateVerify');
  assert.equal(cv.checks[0].status, 'failed');
  assert.equal(messageEvent(t, 'Certificate').checks[0].status, 'passed', 'the chain itself is untouched');
  assert.ok(t.events.some((e) => e.kind === 'response-head'), 'the rest of the timeline is intact');
});

// Regression: crypto.verify with an EC key ignores RSA-PSS options and a null digest, so a
// mismatched scheme used to verify as plain ECDSA-SHA256 and was reported as "passed".
for (const [scheme, name] of [[0x0804, 'rsa_pss_rsae_sha256'], [0x0807, 'ed25519'], [0x0503, 'ecdsa_secp384r1_sha384']]) {
  test(`a scheme that does not fit the certificate's key (${name}) fails, never passes`, () => {
    const check = certificateVerifyCheck(withServerHandshake((h) => h.writeUInt16BE(scheme, algorithmField.offset)));
    assert.equal(check.status, 'failed');
    assert.match(check.reason, /requires|does not match/);
  });
}

test('a signature check that throws is unavailable, not passed', async () => {
  const { signatureStatus } = await import('../src/tls/certificates.js');
  const result = signatureStatus({ verify() { throw new Error('unsupported key'); } }, { publicKey: null });
  assert.deepEqual([result.status, /unsupported key/.test(result.reason)], ['unavailable', true]);
});

// ---- transcript completeness ------------------------------------------------------------------

test('CertificateRequest from a real local TLS server is part of the transcript, in order', async (t) => {
  const tls = await import('node:tls');
  const { recordHttpsGet } = await import('../src/tls/recorder.js');
  const { serializeSession } = await import('../src/session.js');
  const { cert, key, listen } = await import('./helpers/local-tls.mjs');
  const options = await listen(t, tls.createServer({ cert, key, minVersion: 'TLSv1.3', requestCert: true, rejectUnauthorized: false }, (socket) => {
    socket.on('error', () => {});
    socket.once('data', () => socket.end('HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n'));
  }));
  const recorded = await recordHttpsGet(options);
  const local = decryptSession(loadSession(serializeSession({ startedAt: Date.now(), host: 'localhost', path: '/', dns: [], tls: recorded })).tls);
  assert.deepEqual(local.server.messages.slice(0, 5).map((m) => m.type), [2, 8, 13, 11, 15], 'SH, EE, CertificateRequest, Certificate, CertificateVerify');
  const check = certificateVerifyCheck(local);
  assert.equal(check.status, 'passed', check.reason);
  assert.match(check.explanation, /ClientHello, ServerHello, EncryptedExtensions, CertificateRequest, Certificate\)/);
  const withoutRequest = { ...local, server: { ...local.server, messages: local.server.messages.filter((m) => m.type !== 13) } };
  assert.equal(certificateVerifyCheck(withoutRequest).status, 'failed', 'leaving CertificateRequest out breaks the signature: it really is in the transcript');
});

const HRR_RANDOM = 'cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c';

test('a HelloRetryRequest handshake (HRR random in ServerHello) is unavailable, not failed', () => {
  const serverHello = server.messages[0];
  const check = certificateVerifyCheck(withServerHandshake((h) => Buffer.from(HRR_RANDOM, 'hex').copy(h, serverHello.offset + 6)));
  assert.equal(check.status, 'unavailable');
  assert.match(check.reason, /HelloRetryRequest/);
});

test('a second ClientHello (retry after HRR) is unavailable, not failed', () => {
  const [hello] = decrypted.client.messages;
  const client = { ...decrypted.client, messages: [hello, { ...hello }, ...decrypted.client.messages.slice(1)] };
  const check = certificateVerifyCheck({ ...decrypted, client });
  assert.equal(check.status, 'unavailable');
  assert.match(check.reason, /HelloRetryRequest/);
});

test('rsa_pss_pss_sha256 (0x0809) is unavailable with the scheme named, not failed', () => {
  const check = certificateVerifyCheck(withServerHandshake((h) => h.writeUInt16BE(0x0809, algorithmField.offset)));
  assert.equal(check.status, 'unavailable');
  assert.match(check.reason, /0x0809 \(rsa_pss_pss_sha256\)/);
});
