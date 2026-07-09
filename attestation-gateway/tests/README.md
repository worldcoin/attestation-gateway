# Integration Tests

## Logging

- We use the `tracing-test` crate to assert that things are properly logged.
- Because integration tests are bundled as a separate crate, the `no-env-filter` feature is required for the create. More info in [their docs](https://docs.rs/tracing-test/latest/tracing_test/#per-crate-filtering)
