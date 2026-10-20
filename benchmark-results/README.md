# Benchmark results

Benchmark output belongs here as JSON Lines after running the direct-versus-proxy test described in the repository README. Generated `*.jsonl` and `*.log` files are ignored by default so host-specific measurements are not accidentally presented as portable results. Add a reviewed result intentionally when preparing a submission.

Record at least the following alongside results:

- source revision and container image digest;
- host CPU, memory, kernel, and Docker versions;
- Rust and OpenSSL versions;
- proxy limits and trust-reload interval;
- upstream/proxy topology;
- request body size, request count, concurrency, and connection reuse;
- whether TLS session resumption was enabled.

The provided driver uses persistent HTTP/1.1 connections per worker and reads each response body completely. Its proxy measurement includes mTLS setup for the first request on each worker connection; later requests amortize that handshake.

The reviewed local reference run and its environment are recorded in the main README. Its image digest identifies the exact runnable artifact used for the measurement; update both the digest and results after any performance-affecting change.
