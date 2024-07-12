# attestation-gateway

Protects app integrity through the Attestation Gateway.

## 🧪 Testing

- The repo includes both unit and integration tests.
- Integration tests require a local KMS version and Redis, use the following commands to run tests,
  ```bash
  docker compose -f docker-compose.test.yml up
  cargo test
  ```
