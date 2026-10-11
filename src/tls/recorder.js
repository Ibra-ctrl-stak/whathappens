// TCP socket -> recording proxy Duplex -> tls.connect.
// Captures ciphertext ("before TLS", what the wire sees) and plaintext ("after TLS").
import net from 'node:net';
import tls from 'node:tls';
import { Duplex } from 'node:stream';

const HTTPS_PORT = 443;
const SESSION_TIMEOUT_MS = 30000;

/** Duplex that forwards to a TCP socket and records every chunk in both directions. */
class RecordingDuplex extends Duplex {
  constructor(socket, onChunk) {
    super();
    this.socket = socket;
    this.onChunk = onChunk;
    // No backpressure (pause/resume): the TLS wrapper over a JS Duplex stalls with it,
    // and one recorded session is small enough to buffer.
    socket.on('data', (chunk) => {
      this.onChunk('in', chunk);
      this.push(chunk);
    });
    socket.on('end', () => this.push(null));
    // Without this the TLS socket never emits 'close' after the server hangs up.
    socket.on('close', () => this.destroy());
    socket.on('error', (err) => this.destroy(err));
  }

  _read() {}

  _write(chunk, _encoding, callback) {
    this.onChunk('out', chunk);
    this.socket.write(chunk, callback);
  }

  _final(callback) {
    this.socket.end(callback);
  }

  _destroy(err, callback) {
    this.socket.destroy();
    callback(err);
  }
}

function connectTcp(ip, port) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: ip, port });
    socket.once('connect', () => resolve(socket));
    socket.once('error', reject);
  });
}

/**
 * Open TLS 1.3 to ip:443 (SNI = servername), send one HTTP/1.1 GET, read until close.
 * Returns the raw wire chunks, the session keylog lines and the decrypted plaintext as seen by Node.
 */
export async function recordHttpsGet({ ip, servername, path = '/' }) {
  const startedAt = performance.now();
  const raw = [];
  const keylog = [];
  const sentChunks = [];
  const receivedChunks = [];
  const record = (dir, chunk) =>
    raw.push({ dir, t: performance.now() - startedAt, bytes: Buffer.from(chunk) });

  const tcp = await connectTcp(ip, HTTPS_PORT);
  const local = { address: tcp.localAddress, port: tcp.localPort };
  const proxy = new RecordingDuplex(tcp, record);

  const tlsInfo = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      secure.destroy();
      reject(new Error(`TLS session did not finish in ${SESSION_TIMEOUT_MS}ms`));
    }, SESSION_TIMEOUT_MS);
    const secure = tls.connect({
      socket: proxy,
      servername,
      minVersion: 'TLSv1.3',
      ALPNProtocols: ['http/1.1'],
    });
    let info = null;
    secure.on('keylog', (line) => keylog.push(line.toString('ascii').trim()));
    secure.once('secureConnect', () => {
      info = {
        protocol: secure.getProtocol(),
        cipher: secure.getCipher(),
        alpn: secure.alpnProtocol,
        authorized: secure.authorized,
        authorizationError: secure.authorizationError ?? null,
      };
      const request = Buffer.from(
        `GET ${path} HTTP/1.1\r\nHost: ${servername}\r\nUser-Agent: whathappens/0.0.1\r\n` +
          'Accept: */*\r\nConnection: close\r\n\r\n',
        'ascii',
      );
      sentChunks.push(request);
      secure.write(request);
    });
    secure.on('data', (chunk) => receivedChunks.push(Buffer.from(chunk)));
    secure.once('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    secure.once('close', () => {
      clearTimeout(timer);
      if (info) resolve(info);
      else reject(new Error('connection closed before the TLS handshake completed'));
    });
  });

  return {
    ip,
    servername,
    local,
    tls: tlsInfo,
    raw,
    keylog,
    plaintext: { sent: Buffer.concat(sentChunks), received: Buffer.concat(receivedChunks) },
  };
}
