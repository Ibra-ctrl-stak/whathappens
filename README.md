# whathappens

**Watch your own request, byte by byte.**

English | [Русский](README.ru.md)

You've read "what happens when you type google.com" a dozen times.
`whathappens` actually does it: it resolves DNS starting from the root
servers, opens the TCP connection, performs the TLS 1.3 handshake and
speaks HTTP/1.1 — then lays out *your* request as an annotated timeline
in your browser. The bytes on screen are the bytes that crossed your
network: your DNS answers, your ClientHello with its SNI, your server's
certificate, your first HTTP response. No root, no Wireshark, no telemetry.

```sh
npm run day1 && npm run serve
```

![timeline, hex view and field tree](docs/screenshot.png)

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
   HTTP headers. Every field has its own byte range; every byte belongs to exactly one field.
5. **Checks the signatures.** The certificate chain up to a root in Node's store, and the
   CertificateVerify signature over the reconstructed handshake transcript.
6. **Shows it all in a page.** Event timeline, hex view, field tree: click a field to highlight
   its bytes, click a byte to find its field.

## Quick start

Requires Node.js 24 (tested on 24.20). No dependencies.

```sh
git clone https://github.com/Ibra-ctrl-stak/whathappens.git
cd whathappens
npm test                      # 179 tests, no network
node day1.mjs                 # live run: DNS → TLS → our own decryption → out/
npm run serve                 # local page on 127.0.0.1 (URL with a token is printed)
npm run timeline              # the same timeline as text in the terminal
```

To open the page without a live run, use the reference session:
`node serve.mjs test/fixtures/github-robots/session.json`.

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
- Live recordings (`out/`: captures, keylogs, `session.json`) never reach git (`.gitignore`).
  The one exception is the reference test session: the keys of a single public session
  (`robots.txt`), see the [fixture README](test/fixtures/github-robots/README.md).
- The local page: `127.0.0.1` only, random port, a 256-bit token in the URL, `Host`/`Origin`
  checks (DNS rebinding protection), a strict CSP without inline scripts, DOM built with
  `textContent` only. The page never receives the keylog or the whole session.
- Text from the network (DNS names, HTTP headers) is escaped: control characters show up as
  `\xNN` and cannot act on the terminal or the page.

## Limitations

- TLS 1.3 only (AES-GCM, ChaCha20-Poly1305), HTTP/1.1, IPv4 and A records.
- Node cannot see the TCP layer (SYN/ACK, loss, retransmissions); an optional capture mode will
  add it (in progress, see the plan).
- Not supported yet: HelloRetryRequest, KeyUpdate, TLS 1.2, chunked/gzip body decoding.
- Some VPN clients block `127.0.0.1` for browsers — the page will not open then.

## Layout

| Path | What is there |
|---|---|
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
