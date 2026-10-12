# Local TLS test credentials

This self-signed certificate and its deliberately public private key are used only by
`test/recorder.test.mjs` on 127.0.0.1. They identify `localhost`, not a public site.
The test explicitly trusts this certificate; the application retains normal certificate
verification. Never use these credentials outside tests. OpenSSL is not needed to run them.
