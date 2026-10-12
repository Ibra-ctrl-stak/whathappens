import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { once } from 'node:events';

const exec = promisify(execFile);
const cli = fileURLToPath(new URL('../cli.mjs', import.meta.url));
const fixture = fileURLToPath(new URL('fixtures/github-robots/session.json', import.meta.url));

test('help and version work outside the project without making a recording', async (t) => {
  const cwd = await mkdtemp(join(tmpdir(), 'whathappens-cli-'));
  t.after(() => rm(cwd, { recursive: true, force: true }));
  const { stdout } = await exec(process.execPath, [cli, '--help'], { cwd });
  assert.match(stdout, /--demo/);
  assert.match(stdout, /--session/);
  assert.match((await exec(process.execPath, [cli, '--version'], { cwd })).stdout, /^\d+\.\d+\.\d+/);
  assert.deepEqual(await readdir(cwd), []);
});

for (const args of [
  ['--demo', 'example.com'], ['--session', fixture, '--demo'], ['--demo', '--timeout', '3'],
  ['example.com', '--timeout', '0'], ['example.com', '--timeout', 'NaN'],
  ['http://example.com'], ['--unknown'], ['--session', 'missing-session.json'],
]) {
  test(`CLI reports invalid arguments without a stack trace: ${args.join(' ')}`, async () => {
    await assert.rejects(exec(process.execPath, [cli, ...args]), (err) => {
      assert.equal(err.code, 1);
      assert.match(err.stderr, /whathappens:/);
      assert.doesNotMatch(err.stderr, /\n\s+at /);
      return true;
    });
  });
}

for (const args of [['--demo'], ['--session', fixture]]) {
  test(`CLI ${args[0]} serves the real fixture from another directory`, { timeout: 5000 }, async (t) => {
    const cwd = await mkdtemp(join(tmpdir(), 'whathappens-demo-'));
    const child = spawn(process.execPath, [cli, ...args], { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    const closed = once(child, 'close');
    t.after(async () => {
      if (child.exitCode === null && child.signalCode === null) child.kill();
      await closed;
      await rm(cwd, { recursive: true, force: true });
    });
    let output = '';
    const url = await new Promise((resolve, reject) => {
      child.stdout.on('data', (chunk) => {
        output += chunk.toString();
        const match = /Open (http:\/\/127\.0\.0\.1:\d+\/[A-Za-z0-9_-]+\/)/.exec(output);
        if (match) resolve(match[1]);
      });
      child.once('error', reject);
      child.once('close', () => reject(new Error(`CLI closed before serving: ${output}`)));
    });
    const page = await fetch(url);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /whathappens/);
    const view = await (await fetch(`${url}timeline.json`)).json();
    assert.equal(view.events.length, 48);
    assert.ok(view.events.some((event) => event.layer === 'http'));
    const index = view.events.findIndex((event) => event.kind === 'handshake-message' && /ClientHello/.test(event.summary));
    assert.ok(index >= 0);
    const bytes = Buffer.from(await (await fetch(`${url}events/${index}/bytes`)).arrayBuffer());
    assert.ok(bytes.includes(Buffer.from('github.com')));
    const fields = await (await fetch(`${url}events/${index}/fields`)).json();
    assert.ok(fields.fields);
    assert.equal((await fetch(new URL('/timeline.json', url))).status, 404);
    assert.deepEqual(await readdir(cwd), [], 'offline modes create no recording files');
    child.kill('SIGINT');
    const [code, signal] = await closed;
    if (process.platform !== 'win32') { assert.equal(code, 0); assert.equal(signal, null); }
  });
}
