// Encrypt TLS 1.3 records for tests, the mirror image of decryptRecord (RFC 8446 §5.2).
import { createCipheriv } from 'node:crypto';

const TAG_LEN = 16;
const IV_LEN = 12;

function nonceFor(iv, seq) {
  const nonce = Buffer.from(iv);
  const seqBuf = Buffer.alloc(8);
  seqBuf.writeBigUInt64BE(BigInt(seq));
  for (let i = 0; i < 8; i += 1) nonce[IV_LEN - 8 + i] ^= seqBuf[i];
  return nonce;
}

/** Whole TLSCiphertext record (header + ciphertext + tag) carrying `content` of `contentType`. */
export function sealRecord(suite, keys, seq, contentType, content) {
  const inner = Buffer.concat([content, Buffer.from([contentType])]);
  const header = Buffer.from([0x17, 0x03, 0x03, 0, 0]);
  header.writeUInt16BE(inner.length + TAG_LEN, 3);
  const cipher = createCipheriv(suite.cipher, keys.key, nonceFor(keys.iv, seq), { authTagLength: TAG_LEN });
  cipher.setAAD(header, { plaintextLength: inner.length });
  const ciphertext = Buffer.concat([cipher.update(inner), cipher.final()]);
  return Buffer.concat([header, ciphertext, cipher.getAuthTag()]);
}
