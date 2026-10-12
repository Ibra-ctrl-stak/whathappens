# whathappens

**Watch your own request, byte by byte.**

English | [Русский](README.ru.md)

You've read "what happens when you type google.com" a dozen times.
`whathappens` actually does it: it resolves DNS starting from the root
servers, opens the TCP connection, performs the TLS 1.3 handshake and
speaks HTTP/1.1 — then lays out *your* request as an annotated timeline
in your browser. Inspect recorded DNS and TLS bytes alongside the decrypted
handshake and HTTP contents: your DNS answers, your ClientHello with its SNI,
your server's certificate, your HTTP response. No root, no Wireshark, no telemetry.

```sh
node cli.mjs github.com/robots.txt
```

## What it does

1. **Iterative DNS with its own packets.** No `dns.lookup`: root server → `.com` →
   authoritative, on hand-built UDP datagrams (RFC 1035). Lost and malformed answers are not
   hidden — they stay in the recording.
2. **Records the TLS session.** `tls.connect` over a recording proxy stream: ciphertext in both
   directions, the session keys from Node's official `keylog` event, and the plaintext Node
   delivered.
3. **Decrypts it by itself.** TLS 1.3 per RFC 8446 (HKDF-Expand-Label, per-epoch keys, AEAD),
   independent of Node's TLS stack — only `node:crypto` primitives.
4. **Parses the fields.** ClientHello/ServerHello with extensions (SNI, ALPN, key_share,
   supported_versions…), certificates (`X509Certificate`), CertificateVerify, NewSessionTicket,
   HTTP headers and chunk sizes/data/trailers. For parsed events, every byte belongs to exactly one leaf field.
   DNS/TCP events have raw bytes without a field tree; X.509 internals are summarized, not dissected.
5. **Checks signatures independently and shows the results.** Selecting the server's
   `Certificate` or `CertificateVerify` handshake event shows our own results, each as
   *passed*, *failed* or *cannot be checked* (with the concrete reason):
   - **CertificateVerify:** the server's signature over the hash of the reconstructed transcript
     (ClientHello, ServerHello, EncryptedExtensions, Certificate), checked with the public key of
     the server's first certificate; the signature scheme must fit that key's type and curve.
   - **Certificate chain signatures:** each certificate's signature checked with the next
     certificate the server sent (issuer name must match), and the last one with a root from
     Node's built-in root store. This is **not** a full trust decision: host name, validity
     dates, certificate constraints (basicConstraints, keyUsage, name constraints), revocation
     and Certificate Transparency are not part of it.

   These are computed from the recorded bytes; they are not network events. Live connections
   are separately verified by Node itself (normal TLS certificate verification); the viewer does
   not present that as our result.
6. **Shows it all in a page.** Event timeline, hex view, field tree: click a field to highlight
   its bytes, click a byte to find its field.

## HTTP bodies

Chunked transfer coding is parsed per [RFC 9112 §7.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1).
Gzip content is decompressed with Node's built-in zlib. Live requests advertise `Accept-Encoding: gzip`.
The original `response-body` stays available; a separate `decoded-body` event contains the
assembled/decompressed bytes with offsets starting at zero. Corrupt or incomplete bodies are
flagged and do not produce a decoded event. Decoding is limited to 4 MiB per intermediate/output
buffer and 10,000 chunk iterations; trailers remain separate from response headers.

Interim `1xx` responses before the final response (for example `103 Early Hints` or
`100 Continue`) are parsed and shown as separate `interim-response` events; they have no body.
Up to 16 interim responses are parsed; beyond that, the remaining bytes are flagged.
`101 Switching Protocols` is shown as a `protocol-switch` event marked unsupported, and the bytes
after it are not parsed as HTTP. Every response keeps absolute offsets in the received stream
(`http/in`) and is timed by the TLS record that delivered its last byte. If a later response is
truncated or malformed, the responses already parsed stay on the timeline and the remaining
bytes become one event marked "damaged"; a stream that ends before the final response gets an
empty "damaged" event that says so.

## Quick start

Requires Node.js 24+. No dependencies or install step. From the project folder:

```sh
npm run demo                              # bundled trace; no external requests
node cli.mjs github.com/robots.txt         # record a chosen HTTPS target and serve its timeline
node cli.mjs "https://example.com/?q=one" --timeout 60
```

Open the printed `http://127.0.0.1:...` URL in your browser. Stop the server with Ctrl+C.
A bare hostname means HTTPS and path `/`. Paths, query strings, IDNs and custom HTTPS ports
are supported. URL fragments are not sent. Redirect responses are displayed, not followed.

Each successful live run saves `session.json` and `keylog.txt` in a new `out/run-*` directory
under the current working directory. The total DNS + TCP + TLS + HTTP deadline is 30 seconds
(`--timeout 1` through `--timeout 300`); retained wire, plaintext and keylog data share a
16 MiB byte budget. A failed live run reports an error and does not save a partial recording.

```sh
node cli.mjs --session out/run-XXXXXX/session.json   # reopen an actual saved file
node cli.mjs --help                                 # all options, including --out
npm test                                           # tests use local sockets; no external requests
```

The package remains unpublished and marked private. `npx whathappens` is not available yet.
The original `node day1.mjs [path]`, `npm run serve` and `npm run timeline` commands remain
available for the original github.com verification workflow, which uses `out/session.json`.

### Checking against Wireshark (optional)

With Wireshark installed (tshark/dumpcap): capture while `node day1.mjs` runs, then
`node compare-wireshark.mjs out/capture.pcapng` compares byte for byte the DNS packets, both TCP
streams, the handshake, and Wireshark's own decryption using our keylog. If your traffic goes
through a VPN, capture on the tunnel interface.

## How it is verified

- **Wireshark as an independent oracle.** The reference session matched a capture byte for byte
  (12/12 checks); the field values in `test/fixtures/github-robots/expected.json` come from
  tshark, not from our code.
- **RFC 8448.** HKDF, traffic keys and record decryption are tested against the official
  vectors, extracted from the RFC text programmatically.
- **Damaged traffic.** Corrupted, truncated and malformed records and messages stay on the
  timeline as events marked "damaged" instead of breaking the rest.
- **Mutation checks** for key tests: a test must fail on deliberately broken code.

## Security and ethics

- The tool only sees **traffic it created itself**, and decrypts it with the keys of its own
  sessions through Node.js's official API. No interception, no circumvention.
- Live recordings (`out/`: captures, keylogs, `session.json`) are excluded by `.gitignore`.
  The one exception is the reference test session: the keys of a single public session
  (`robots.txt`), see the [fixture README](test/fixtures/github-robots/README.md).
  Local TLS tests also include deliberately public localhost-only test credentials.
  Treat your live recordings as sensitive: they contain the keys and contents of that request.
- The local page: `127.0.0.1` only, random port, a 256-bit token in the URL, `Host`/`Origin`
  checks (DNS rebinding protection), a strict CSP without inline scripts, DOM built with
  `textContent` only. The page never receives the keylog or the whole session.
- Text from the network (DNS names, HTTP headers) is escaped: control characters show up as
  `\xNN` and cannot act on the terminal or the page.

## Limitations

- TLS 1.3 only (AES-GCM, ChaCha20-Poly1305), HTTP/1.1, IPv4 and A records.
- Node cannot see the TCP layer (SYN/ACK, loss, retransmissions); an optional capture mode will
  add it (planned, see the plan).
- Not supported yet: HelloRetryRequest, KeyUpdate, TLS 1.2, Brotli/deflate, transfer-coding chains, protocol upgrades after `101`, more than one final response on a connection (pipelining), HTTP/2.
- Direct UDP/53 access to authoritative DNS servers is required for live mode; use `--demo`
  on networks that block it. HTTP-only targets and IP-literal URLs are not supported.
- Some VPN clients block `127.0.0.1` for browsers — the page will not open then.

## Layout

| Path | What is there |
|---|---|
| `cli.mjs`, `src/capture.js`, `src/target.js`, `src/viewer.js` | CLI, recording, URL validation, viewer startup |
| `src/dns/` | DNS packets and the iterative resolver |
| `src/tls/` | session recording, decryption, handshake fields, certificates and signatures |
| `src/http/` | HTTP/1.1 parsing and its fields |
| `src/timeline.js` | the unified event timeline `{ buffer, offset, length, fields }` |
| `src/server/`, `web/` | the local page |
| `test/` | tests, the fixture, RFC 8448 vectors |
| `tools/` | extracting the oracle from tshark and the vectors from RFC 8448 |

Progress and next steps: [PLAN.md](PLAN.md) (in Russian).

## License

[MIT](LICENSE) © 2026 Ibra-ctrl-stak.
