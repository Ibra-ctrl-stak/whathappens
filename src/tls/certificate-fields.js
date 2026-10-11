// Certificate message (RFC 8446 §4.4.2) fields; each cert_data is decoded with X509Certificate.
// The DER internals are not mapped byte by byte: cert_data carries the decoded summary instead.
import { X509Certificate } from 'node:crypto';
import { extensions } from './extensions.js';

const U24 = 3;

/** What a visualizer shows for one certificate. JSON-safe (no BigInt, no KeyObject). */
export function describeCertificate(der) {
  const x = new X509Certificate(der);
  const { asymmetricKeyType, asymmetricKeyDetails = {} } = x.publicKey;
  return {
    subject: x.subject,
    issuer: x.issuer,
    serialNumber: x.serialNumber,
    validFrom: x.validFromDate.toISOString(),
    validTo: x.validToDate.toISOString(),
    dnsNames: (x.subjectAltName ?? '').split(', ').filter((n) => n.startsWith('DNS:')).map((n) => n.slice(4)),
    signatureAlgorithm: x.signatureAlgorithm ?? null,
    publicKey: { type: asymmetricKeyType, curve: asymmetricKeyDetails.namedCurve ?? null, bits: asymmetricKeyDetails.modulusLength ?? null },
    ca: x.ca,
    fingerprint256: x.fingerprint256,
  };
}

function decoded(der) {
  try {
    const x509 = describeCertificate(der);
    const cn = x509.subject.split('\n').find((line) => line.startsWith('CN=')) ?? null;
    return { value: cn, x509 };
  } catch (err) {
    return { problem: `certificate does not decode: ${err.message}` };
  }
}

function certificateEntry(c, stream) {
  const data = c.opaque('cert_data', U24, () => null);
  const der = stream.subarray(data.offset + U24, data.offset + data.length);
  return c.group('certificate_entry', [{ ...data, ...decoded(der) }, extensions(c, 'certificate')]);
}

export const certificateBody = (c, stream) => [
  c.opaque('certificate_request_context', 1),
  c.vector('certificate_list', U24, (body) => body.many((x) => certificateEntry(x, stream))),
];
