import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { capture, saveRecording } from '../src/capture.js';
import { loadSession } from '../src/session.js';
import { decryptSession } from '../src/tls/decrypt.js';

const fixture = JSON.parse(await readFile(new URL('fixtures/github-robots/session.json', import.meta.url), 'utf8'));

test('capture propagates the chosen hostname, path and port and serializes the DNS trace', async () => {
  const session = loadSession(fixture);
  const decrypted = decryptSession(session.tls);
  const progress = [];
  const result = await capture('https://example.com:8443/a?x=1', { onProgress: (line) => progress.push(line) }, {
    resolveHost: async (name, options) => {
      assert.equal(name, 'example.com');
      session.dns.forEach(options.onExchange);
      return ['192.0.2.10'];
    },
    record: async (options) => {
      assert.equal(options.servername, 'example.com');
      assert.equal(options.ip, '192.0.2.10');
      assert.equal(options.port, 8443);
      assert.equal(options.path, '/a?x=1');
      return { ...session.tls, tls: session.tls.info,
        plaintext: { sent: decrypted.client.appData, received: decrypted.server.appData } };
    },
  });
  assert.equal(result.host, 'example.com');
  assert.equal(result.path, '/a?x=1');
  assert.equal(result.dns.length, fixture.dns.length);
  assert.ok(progress.length > 1);
  assert.doesNotThrow(() => loadSession(result));
});

test('the total request deadline aborts DNS before a TLS attempt', { timeout: 1000 }, async () => {
  let recordCalls = 0;
  await assert.rejects(capture('example.com', { timeoutMs: 25 }, {
    resolveHost: (_name, { signal }) => new Promise((_resolve, reject) => {
      signal.addEventListener('abort', () => reject(signal.reason), { once: true });
    }),
    record: async () => { recordCalls += 1; },
  }), /timed out.*DNS/);
  assert.equal(recordCalls, 0);
});

test('separate recordings never overwrite each other and can be loaded again', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'whathappens-save-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const first = await saveRecording(fixture, directory);
  const second = await saveRecording({ ...fixture, host: 'second.example' }, directory);
  assert.notEqual(first, second);
  assert.equal(JSON.parse(await readFile(first, 'utf8')).host, fixture.host);
  assert.equal(JSON.parse(await readFile(second, 'utf8')).host, 'second.example');
  const loaded = loadSession(JSON.parse(await readFile(first, 'utf8')));
  assert.deepEqual(decryptSession(loaded.tls).server.appData, decryptSession(loadSession(fixture).tls).server.appData);
  assert.equal(await readFile(join(dirname(first), 'keylog.txt'), 'utf8'), `${fixture.tls.keylog.join('\n')}\n`);
  if (process.platform !== 'win32') assert.equal((await stat(first)).mode & 0o777, 0o600);
});
