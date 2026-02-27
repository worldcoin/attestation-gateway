# attestation-gateway

Protects app integrity through the Attestation Gateway.

## 🧪 Testing

- The repo includes both unit and integration tests.
- On macOS you need to install `openssl` if you haven't already: `brew install pkg-config openssl@3`
- Integration tests require a local KMS version and Redis, use the following commands to run tests,
  ```bash
  docker compose -f attestation-gateway/tests/docker-compose.test.yml up -d
  cargo test
  ```
