// A real TLS 1.3 server on 127.0.0.1 for tests, with the public localhost-only test credentials
// (see test/fixtures/localhost-tls/README.md). Closed with its sockets when the test ends.
import { readFileSync } from 'node:fs';
import { once } from 'node:events';

export const cert = readFileSync(new URL('../fixtures/localhost-tls/cert.pem', import.meta.url));
export const key = readFileSync(new URL('../fixtures/localhost-tls/key.pem', import.meta.url));

/** Start `server` on loopback; returns recordHttpsGet options that trust its certificate. */
export async function listen(t, server) {
  const sockets = new Set();
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('error', () => {});
    socket.once('close', () => sockets.delete(socket));
  });
  server.on('tlsClientError', () => {});
  t.after(() => {
    for (const socket of sockets) socket.destroy();
    server.close();
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return { ip: '127.0.0.1', servername: 'localhost', port: server.address().port, ca: cert };
}
