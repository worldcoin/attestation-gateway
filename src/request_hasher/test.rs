use super::*;

/// This test should be identical to TypeScript's risk-verdict test from the app-backend-main repo.
/// [Reference](https://github.com/worldcoin/app-backend-main/blob/0abd17a29425059c1e2e3ce8366e002b9dd1995e/src/lib/decorators/risk-verdict.guard.spec.ts)
#[test]
fn test_generate_request_hash() {
    let input = GenerateRequestHashInput {
        method: AllowedHttpMethod::Post,
        path_uri: "/dev/redis-get-protected".to_string(),
        body: Some(
            serde_json::json!({
                        "cField": "value3",
                        "aField": 123,
                        "bField": ["item1", "item2"],
                        "nestedField": {
                            "bNested": "nestedValue2",
                            "aNested": "nestedValue1",
                            "cNested": 456,
                        },
                        "risk": {
                            "appVersion": "2.7.5302",
                            "clientName": "android",
                            "publicKeyId": "public-key-id",
                            "iOSDeviceToken": "iosDeviceTokenValue",
                            "iOSDeviceTokenError": "no_token_error",
                        }
            })
            .to_string(),
        ),
    };

    let hasher = RequestHasher::new();
    let hash = hasher.generate_json_request_hash(&input).unwrap();

    assert_eq!(
        hash, "feaf752bde3c9ac349850602f76888ba57f165e8137291369ee9343883ad0be0",
        "The generated hash does not match the expected value."
    );
}
