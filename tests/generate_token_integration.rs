use axum::{
    body::Body,
    http::{self, Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt; // for `collect`

use attestation_gateway::utils::{BundleIdentifier, TokenGenerationRequest};

#[tokio::test]
async fn test_token_generation() {
    let api_router = attestation_gateway::routes::handler();

    let token_generation_request = TokenGenerationRequest {
        integrity_token: "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0.cNECHTrf6KAJDjDGqkWF4O0uMey-S4rjJYV9GNuyVGZlSOJV_4VaTg.gC6osYvLIhvwroOJ.EYkQCz4FFVNdRozPflriVz23J4AkP3FXnYU-p2IzEp9I5GHsYnEQg8CHCx_bNRBP_kUiWKjUDNW7XV-f1xHp-F8lDhuda-eouMdzdzphbQPw_jCEo3ujN-i6tO8NWUqOX3L8IhYQxDilz3yQ6j5_2ESlrNfm9J2KO9UaK5xAvNvUeplDCuG9DbAjoiqyKo1F7Arezqqo7M0NeMMD3EWVf36Pqx3_Fna14wdUx6mRQeMcZ5wYtQprU7mJXGIPoCGvdNuSzwM1Hcgmey8mp7HLXTQP1EXrogzSoGkTdZomfz0wnrB8WkLT5wDg3eb1lhYbih9SwupTrakAQG9LdBAWEldO_GzX1JW6zI51tZIUlWjyNhNrWJtyYNAYSSbc9dY4qN5ffNd0vhVlMB5DWD6v-ztaPASG3776e_mfgYsCEd_1PsrW3CbuVY-m5fva2qi0ar1Hye5ZSrE267ND_2CIvjqnEjDKji3S3PepTlbPv1_VGzRrra9QpuJKVKxefeoNGwZ-U8jDeJCErfFdOFJaXJ94McnO0IWc6aoEQf3stzqTEsx_T9MIP6n8TGx-w0xG-WJIVu_P1nb5Ybva8F8oqgtZwhuTGnin3ErSlHAn8HpdJ3-2T0BMuvf8ITfBgdSvS_aMJTPfPp3M8K0O-LN-6fGDZc-brKv_i7s-VQZj6w6D-EJ9xwGbXwxOk7mkyIAseUS-SEXNxG1OcC4QT-e47ncyq2C_KzR3-5spdzCg0FdxvqDuBhj8G2rd-LeElXohmITmJ3Ee_VafaFiYGcRzJdr6wfgF-LJoGNr8GMDxcEH9tIAZwDn6f3BearErgn8EJFrNhMDcallTWQX1AoPlCEhaJBB0RB5L0grAqOqkhM5XqrqzYBUIiIP3Cs1LQSmy2Ai2z6iOaKfyOU_rNXq_jhGmvr9u9PBYjnZhnnOoSVmNp8PkGdb8pLrL_LzMuHundTFOZUsbz3tgyqKzh8dae-Yf6D5u_byCUyMscnLL9Q520NfWnXtHVYJCWZOeU9F693MFUUE4aOuEZFfSk998QTSEFf-TagC7vP2rH4Zpux0sCM2hqxjOOvZEyg3Ef8FsBvg9srRIIb_L5mpVa0jasTyqfyDVECxZO4YiqZW5CWPWLDfgT2MkYPOT8VclhZ5ZyJIKu7ZamNGriSZBhHjKQi2g0ap9A75qnyrdq-hEJZo4gqKmUou9f3fQAzT3sCPj1i3PEWVmHQvlt5vbDTqmBBxyLcgSkd0oNrpI-So2jf94syvImh_5OKexCdde5Fj91o8.5_KKK0EuQwEA5tjlpxaRzA".to_string(),
                aud: "toolsforhumanity.com".to_string(),
        bundle_identifier: BundleIdentifier::AndroidDevWorldApp,
        request_hash: "aGVsbG8gd29scmQgdGhlcmU".to_string(),
        client_error: None,
        apple_initial_attestation: None,
        apple_public_key: None,
    };

    let body = serde_json::to_string(&token_generation_request).unwrap();

    let response = api_router
        .oneshot(
            Request::builder()
                .uri("/g")
                .method(http::Method::POST)
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        body,
        json!({ "attestation_gateway_token": "my_token".to_string() })
    );
}

#[tokio::test]
async fn test_token_generation_fails_on_invalid_bundle_identifier() {
    let api_router = attestation_gateway::routes::handler();

    let token_generation_request = json!( {
        "integrity_token": "my_integrity_token".to_string(),
        "aud": "toolsforhumanity.com".to_string(),
        "bundle_identifier": "com.worldcoin.invalid".to_string(),
        "request_hash": "my_request_hash".to_string(),
    });

    let body = serde_json::to_string(&token_generation_request).unwrap();

    let response = api_router
        .oneshot(
            Request::builder()
                .uri("/g")
                .method(http::Method::POST)
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        body["schema_validation"][0]["instance_location"],
        "/bundle_identifier".to_string()
    );
}
