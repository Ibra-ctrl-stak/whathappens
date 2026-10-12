// exchange() over real UDP on loopback: only a genuine answer from server:port ends the wait.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import { once } from 'node:events';
import { exchange } from '../src/dns/iterative.js';
import { buildQuery, TYPE } from '../src/dns/packet.js';

const QR_BIT = 0x80;
const asResponse = (query) => {
  const r = Buffer.from(query);
  r[2] |= QR_BIT;
  return r;
};

async function udpSocket() {
  const socket = dgram.createSocket('udp4');
  socket.bind(0, '127.0.0.1');
  await once(socket, 'listening');
  return socket;
}

test('ignores spoofed datagrams and resolves with the genuine answer', async (t) => {
  const server = await udpSocket();
  const intruder = await udpSocket(); // same IP, wrong source port
  t.after(() => {
    server.close();
    intruder.close();
  });
  const query = buildQuery({ id: 0x2222, name: 'github.com', type: TYPE.A });
  const genuine = asResponse(query);
  const forged = Buffer.from(genuine);
  forged[2] |= 0x04; // AA set: a valid answer to our question, but distinguishable from the genuine one

  server.once('message', (msg, client) => {
    const send = (sock, buf) => sock.send(buf, client.port, client.address);
    send(intruder, forged); // matching answer, wrong source port
    send(server, asResponse(buildQuery({ id: 0x3333, name: 'github.com' }))); // wrong id
    send(server, msg); // QR clear: an echo of the query
    send(server, asResponse(buildQuery({ id: 0x2222, name: 'evil.example' }))); // wrong question
    setTimeout(() => send(server, genuine), 50);
  });

  const target = { name: 'loopback', ip: '127.0.0.1', port: server.address().port };
  const { response } = await exchange(target, query);
  assert.deepEqual(response, genuine);
});

test('cancellation interrupts a pending DNS datagram', { timeout: 1000 }, async (t) => {
  const server = await udpSocket();
  t.after(() => server.close());
  const controller = new AbortController();
  const received = once(server, 'message');
  const pending = exchange({ name: 'loopback', ip: '127.0.0.1', port: server.address().port },
    buildQuery({ id: 123, name: 'example.com' }), { signal: controller.signal });
  await received;
  controller.abort(new Error('stop DNS now'));
  await assert.rejects(pending, /stop DNS now/);
});
