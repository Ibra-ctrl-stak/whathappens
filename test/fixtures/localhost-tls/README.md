# Local TLS test credentials

`cert.pem` is a self-signed certificate for `localhost`. `key.pem` is its **private key**
(not a public key), published here on purpose: it is a test-only key, so anyone may read it.
It identifies no public site and protects nothing.

They are used only by local TLS servers on 127.0.0.1 in `test/recorder.test.mjs`,
`test/handshake-checks.test.mjs` and `test/http-interim-tls.test.mjs` (through
`test/helpers/local-tls.mjs`). Those tests explicitly trust this certificate; the application
itself keeps normal certificate verification. Never use these credentials outside tests.
OpenSSL is not needed to run them.
