// TLS 1.3 record decryption (RFC 8446 §5.2, §7.1, §7.3) from recorded wire bytes + keylog secrets.
// Deliberately independent from Node's TLS stack: only HMAC and AEAD primitives from node:crypto.
import { createHmac, createDecipheriv } from 'node:crypto';

const CONTENT = Object.freeze({ CCS: 20, ALERT: 21, HANDSHAKE: 22, APP_DATA: 23 });
const HANDSHAKE = Object.freeze({ CLIENT_HELLO: 1, SERVER_HELLO: 2, FINISHED: 20 });
const RECORD_HEADER_LEN = 5;
const AEAD_TAG_LEN = 16;
const IV_LEN = 12;
// RFC 8446 §4.1.3: ServerHello.random of a HelloRetryRequest
const HRR_RANDOM = 'cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c';

export const SUITES = Object.freeze({
  0x1301: { name: 'TLS_AES_128_GCM_SHA256', hash: 'sha256', cipher: 'aes-128-gcm', keyLen: 16 },
  0x1302: { name: 'TLS_AES_256_GCM_SHA384', hash: 'sha384', cipher: 'aes-256-gcm', keyLen: 32 },
  0x1303: { name: 'TLS_CHACHA20_POLY1305_SHA256', hash: 'sha256', cipher: 'chacha20-poly1305', keyLen: 32 },
});

export function parseKeylog(lines) {
  const entries = lines
    .map((l) => l.trim().split(/\s+/))
    .filter((parts) => parts.length === 3 && !parts[0].startsWith('#'));
  const randoms = new Set(entries.map(([, random]) => random.toLowerCase()));
  if (randoms.size !== 1) throw new Error(`expected one client_random in keylog, got ${randoms.size}`);
  return {
    clientRandom: [...randoms][0],
    secrets: Object.fromEntries(entries.map(([label, , secret]) => [label, Buffer.from(secret, 'hex')])),
  };
}

/** HKDF-Expand (RFC 5869 §2.3). */
function hkdfExpand(hash, prk, info, length) {
  const blocks = [];
  let prev = Buffer.alloc(0);
  for (let i = 1; Buffer.concat(blocks).length < length; i += 1) {
    prev = createHmac(hash, prk).update(Buffer.concat([prev, info, Buffer.from([i])])).digest();
    blocks.push(prev);
  }
  return Buffer.concat(blocks).subarray(0, length);
}

/** HKDF-Expand-Label (RFC 8446 §7.1). */
export function hkdfExpandLabel(hash, secret, label, context, length) {
  const fullLabel = Buffer.from(`tls13 ${label}`, 'ascii');
  const info = Buffer.concat([
    Buffer.from([length >> 8, length & 0xff, fullLabel.length]),
    fullLabel,
    Buffer.from([context.length]),
    context,
  ]);
  return hkdfExpand(hash, secret, info, length);
}

export function trafficKeys(suite, secret) {
  return {
    key: hkdfExpandLabel(suite.hash, secret, 'key', Buffer.alloc(0), suite.keyLen),
    iv: hkdfExpandLabel(suite.hash, secret, 'iv', Buffer.alloc(0), IV_LEN),
  };
}

/** Split a byte stream into TLS records. */
export function splitRecords(stream) {
  const records = [];
  let pos = 0;
  while (pos + RECORD_HEADER_LEN <= stream.length) {
    const length = stream.readUInt16BE(pos + 3);
    const end = pos + RECORD_HEADER_LEN + length;
    if (end > stream.length) break;
    records.push({
      offset: pos,
      type: stream[pos],
      version: stream.readUInt16BE(pos + 1),
      header: stream.subarray(pos, pos + RECORD_HEADER_LEN),
      body: stream.subarray(pos + RECORD_HEADER_LEN, end),
    });
    pos = end;
  }
  return { records, trailing: stream.length - pos };
}

function nonceFor(iv, seq) {
  const nonce = Buffer.from(iv);
  const seqBuf = Buffer.alloc(8);
  seqBuf.writeBigUInt64BE(BigInt(seq));
  for (let i = 0; i < 8; i += 1) nonce[IV_LEN - 8 + i] ^= seqBuf[i];
  return nonce;
}

/** Decrypt one TLSCiphertext; returns TLSInnerPlaintext split into content + real type. */
export function decryptRecord(suite, keys, seq, record) {
  const ciphertext = record.body.subarray(0, record.body.length - AEAD_TAG_LEN);
  const tag = record.body.subarray(record.body.length - AEAD_TAG_LEN);
  const decipher = createDecipheriv(suite.cipher, keys.key, nonceFor(keys.iv, seq), {
    authTagLength: AEAD_TAG_LEN,
  });
  decipher.setAAD(record.header, { plaintextLength: ciphertext.length });
  decipher.setAuthTag(tag);
  const inner = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  let end = inner.length - 1;
  while (end >= 0 && inner[end] === 0) end -= 1; // strip zero padding
  if (end < 0) throw new Error('inner plaintext has no content type');
  return { contentType: inner[end], content: inner.subarray(0, end) };
}

/** Parse complete handshake messages out of a buffer; returns messages and unconsumed rest. */
function takeHandshakeMessages(buf) {
  const messages = [];
  let pos = 0;
  while (pos + 4 <= buf.length) {
    const len = buf.readUIntBE(pos + 1, 3);
    if (pos + 4 + len > buf.length) break;
    messages.push({ type: buf[pos], body: buf.subarray(pos + 4, pos + 4 + len) });
    pos += 4 + len;
  }
  return { messages, rest: buf.subarray(pos) };
}

function helloInfo(records, expectedType) {
  const first = records.find((r) => r.type === CONTENT.HANDSHAKE);
  if (!first) throw new Error('no plaintext handshake record');
  const { messages } = takeHandshakeMessages(first.body);
  const hello = messages.find((m) => m.type === expectedType);
  if (!hello) throw new Error(`handshake type ${expectedType} not found in first record`);
  const random = hello.body.subarray(2, 34).toString('hex');
  const sidLen = hello.body[34];
  return { random, body: hello.body, afterSessionId: 35 + sidLen };
}

/**
 * Walk one direction: plaintext hello -> handshake epoch (until Finished) -> application epoch.
 * Each epoch has its own keys and its own sequence counter starting at 0.
 */
function decryptDirection(records, suite, hsSecret, appSecret) {
  const epochs = { handshake: trafficKeys(suite, hsSecret), application: trafficKeys(suite, appSecret) };
  let epoch = 'handshake';
  let seq = 0;
  let pendingHandshake = Buffer.alloc(0);
  const out = [];
  for (const record of records) {
    if (record.type !== CONTENT.APP_DATA) {
      out.push({ offset: record.offset, epoch: 'plaintext', outerType: record.type, length: record.body.length });
      continue;
    }
    const { contentType, content } = decryptRecord(suite, epochs[epoch], seq, record);
    const entry = { offset: record.offset, epoch, seq, outerType: record.type, contentType, content };
    seq += 1;
    if (epoch === 'handshake' && contentType === CONTENT.HANDSHAKE) {
      const { messages, rest } = takeHandshakeMessages(Buffer.concat([pendingHandshake, content]));
      pendingHandshake = rest;
      entry.handshakeTypes = messages.map((m) => m.type);
      if (messages.some((m) => m.type === HANDSHAKE.FINISHED)) {
        epoch = 'application';
        seq = 0;
      }
    }
    out.push(entry);
  }
  const appData = Buffer.concat(
    out.filter((e) => e.epoch === 'application' && e.contentType === CONTENT.APP_DATA).map((e) => e.content),
  );
  return { records: out, appData };
}

export function streamsFromRaw(raw) {
  const join = (dir) => Buffer.concat(raw.filter((c) => c.dir === dir).map((c) => c.bytes));
  return { client: join('out'), server: join('in') };
}

export function decryptSession({ raw, keylog }) {
  const { clientRandom, secrets } = parseKeylog(keylog);
  const streams = streamsFromRaw(raw);
  const client = splitRecords(streams.client);
  const server = splitRecords(streams.server);

  const clientHello = helloInfo(client.records, HANDSHAKE.CLIENT_HELLO);
  if (clientHello.random !== clientRandom) {
    throw new Error('keylog client_random does not match the recorded ClientHello');
  }
  const serverHello = helloInfo(server.records, HANDSHAKE.SERVER_HELLO);
  if (serverHello.random === HRR_RANDOM) throw new Error('HelloRetryRequest is not supported yet');
  const suiteId = serverHello.body.readUInt16BE(serverHello.afterSessionId);
  const suite = SUITES[suiteId];
  if (!suite) throw new Error(`unsupported cipher suite 0x${suiteId.toString(16)}`);

  const need = (label) => {
    if (!secrets[label]) throw new Error(`keylog is missing ${label}`);
    return secrets[label];
  };
  return {
    suite: { id: suiteId, ...suite },
    clientRandom,
    trailingBytes: { client: client.trailing, server: server.trailing },
    client: decryptDirection(
      client.records,
      suite,
      need('CLIENT_HANDSHAKE_TRAFFIC_SECRET'),
      need('CLIENT_TRAFFIC_SECRET_0'),
    ),
    server: decryptDirection(
      server.records,
      suite,
      need('SERVER_HANDSHAKE_TRAFFIC_SECRET'),
      need('SERVER_TRAFFIC_SECRET_0'),
    ),
  };
}
