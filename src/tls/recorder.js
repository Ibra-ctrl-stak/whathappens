// TCP socket -> recording Duplex -> Node TLS. All traffic belongs to this request.
import net from 'node:net';
import tls from 'node:tls';
import { Duplex } from 'node:stream';
import { nowMs } from '../clock.js';
import { validateHostname, validatePath } from '../target.js';

export const DEFAULT_MAX_BYTES = 16 * 1024 * 1024;
const SESSION_TIMEOUT_MS = 30000;

class RecordingDuplex extends Duplex {
  constructor(socket, onChunk) {
    super();
    this.socket = socket;
    this.onChunk = onChunk;
    // TLS over a JS Duplex stalls with pause/resume here. A byte budget bounds buffering.
    socket.on('data', (chunk) => {
      try { this.onChunk('in', chunk); this.push(chunk); }
      catch (err) { this.destroy(err); }
    });
    socket.on('end', () => this.push(null));
    socket.on('close', () => this.destroy());
    socket.on('error', (err) => this.destroy(err));
  }
  _read() {}
  _write(chunk, _encoding, callback) {
    try { this.onChunk('out', chunk); this.socket.write(chunk, callback); }
    catch (err) { callback(err); }
  }
  _final(callback) { this.socket.end(callback); }
  _destroy(err, callback) { this.socket.destroy(); callback(err); }
}

function connectTcp(ip, port, signal) {
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: ip, port });
    const abort = () => { socket.destroy(); reject(signal.reason); };
    signal.addEventListener('abort', abort, { once: true });
    socket.once('connect', () => {
      signal.removeEventListener('abort', abort);
      resolve(socket);
    });
    socket.once('error', (err) => {
      signal.removeEventListener('abort', abort);
      reject(err);
    });
    socket.once('close', () => signal.removeEventListener('abort', abort));
  });
}

/**
 * Send one HTTP/1.1 GET over verified TLS 1.3. timeoutMs includes TCP connection time.
 * maxBytes limits retained wire + plaintext bytes together. ca is an optional trust store
 * (used by localhost tests); certificate verification is never disabled.
 */
export async function recordHttpsGet({
  ip, servername, path = '/', port = 443, timeoutMs = SESSION_TIMEOUT_MS,
  maxBytes = DEFAULT_MAX_BYTES, signal, ca,
}) {
  validateHostname(servername);
  validatePath(path);
  if (!net.isIPv4(ip)) throw new Error('The recorder needs an IPv4 address from DNS.');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid HTTPS port.');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 2147483647) throw new Error('Invalid timeout.');
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new Error('Invalid byte limit.');
  signal?.throwIfAborted();
  const deadline = new AbortController();
  const activeSignal = signal ? AbortSignal.any([signal, deadline.signal]) : deadline.signal;
  const timer = setTimeout(() => deadline.abort(new Error(`TCP/TLS request timed out after ${timeoutMs}ms.`)), timeoutMs);
  const raw = [], keylog = [], sentChunks = [], receivedChunks = [];
  let retainedBytes = 0;
  const reserve = (length) => {
    if (retainedBytes + length > maxBytes) throw new Error(`Recording byte limit exceeded (${maxBytes} bytes). Try a smaller resource.`);
    retainedBytes += length;
  };
  const record = (dir, chunk) => {
    reserve(chunk.length);
    raw.push({ dir, at: nowMs(), bytes: Buffer.from(chunk) });
  };
  const times = { connectStartedAt: nowMs(), connectedAt: null, secureAt: null, closedAt: null };
  let tcp, proxy, secure;
  try {
    tcp = await connectTcp(ip, port, activeSignal);
    activeSignal.throwIfAborted();
    times.connectedAt = nowMs();
    tcp.once('close', () => { times.closedAt ??= nowMs(); });
    const local = { address: tcp.localAddress, port: tcp.localPort };
    proxy = new RecordingDuplex(tcp, record);
    const tlsInfo = await new Promise((resolve, reject) => {
      let info = null;
      const fail = (err) => {
        reject(err);
        secure?.destroy();
        proxy.destroy();
      };
      const abort = () => fail(activeSignal.reason);
      proxy.on('error', fail);
      secure = tls.connect({
        socket: proxy, servername, ca,
        minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', ALPNProtocols: ['http/1.1'],
      });
      activeSignal.addEventListener('abort', abort, { once: true });
      secure.on('keylog', (line) => {
        try { reserve(line.length); keylog.push(line.toString('ascii').trim()); }
        catch (err) { fail(err); }
      });
      secure.once('secureConnect', () => {
        try {
          times.secureAt = nowMs();
          info = {
            protocol: secure.getProtocol(), cipher: secure.getCipher(), alpn: secure.alpnProtocol,
            authorized: secure.authorized, authorizationError: secure.authorizationError ?? null,
          };
          const authority = port === 443 ? servername : `${servername}:${port}`;
          const request = Buffer.from(
            `GET ${path} HTTP/1.1\r\nHost: ${authority}\r\nUser-Agent: whathappens/0.0.1\r\n` +
            'Accept: */*\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n', 'ascii',
          );
          reserve(request.length);
          sentChunks.push(request);
          secure.write(request);
        } catch (err) { fail(err); }
      });
      secure.on('data', (chunk) => {
        try { reserve(chunk.length); receivedChunks.push(Buffer.from(chunk)); }
        catch (err) { fail(err); }
      });
      secure.once('error', fail);
      secure.once('close', () => {
        activeSignal.removeEventListener('abort', abort);
        times.closedAt ??= nowMs();
        if (info) resolve(info);
        else reject(new Error('Connection closed before the TLS 1.3 handshake completed.'));
      });
      if (activeSignal.aborted) abort();
    });
    return {
      ip, port, servername, local, tls: tlsInfo, times, raw, keylog,
      plaintext: { sent: Buffer.concat(sentChunks), received: Buffer.concat(receivedChunks) },
    };
  } finally {
    clearTimeout(timer);
    secure?.destroy();
    proxy?.destroy();
    tcp?.destroy();
  }
}
