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
        integrity_token: "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0.AETObD_5IY0mwKzEedlxpo2_yJQ9sd1_UX2svMi4rQZjL8wo8qvPYw.cJBf3pdpR-mM-GRi.p-iwPfzS_JVQg9slJo_p62TUEdHvDMdRVHMA6555BNvZq2IEgqoRJgKfAMw4p2XNPnIccsQdrYZ6nyQC4QmC5yCGYxYZNzwpVzQ_fdFtjZihxrEvfVWBtt1BttEJH-24TTiN_Jo_U8Quuu9hiItruNpBJBQi-853urlNXZA1LFxqnlSDr6xLGBlJf5loURJR2DlrdzmokJ5ymj9vDuIsgkIQnodyWHukD83o4Ia9Ott-zwb4rCF0CdwlgLucDU8r2rcyCcf3EE-UjrKTwgE2XLbHAxclfi7ywudUZe3SGrCFTHr3mU70yoQTAZdNIdddIzAExt5-g3W-BwuSU7GjL2ZHnTEHCxMGWKPdTN1_lBpIXHlqx0N86YN5lBpoHvZE515Ibd05RA56ziRz_HN2M-wIG9xBR2BsPjmHtc0iu8MSv-hV2Qv973xVnd5kpoqthYTN6LhQj0zIsqJSqDxL14TXrDVeBbe8WvNIG8K0WDX9wVsujI0x4cqpKB1DzJ9lElqfkFKFRhctLWqXP9PyX_ubAGwzQebCNfzemPXr1dmENM_mFwUYcLdBZtGPY2k-xor81hf9IWvAnL18U48VwYh7jZTXv4-47wezYfV38wFiAi-Wk36xmzJ8_AzsMvBYosLEH5jGk5vmL-jhxMwUnwuI0cNp-IC4UZ80gKu_Dybwshjd7Ju8VJyWW2Q_uu7JJxEMEcsYrjtLh7dC1DN-QAOkMixa0t5dYrrMJX7uypJJd1MJOU8cM0ZzfZJosFpeyEuo-_anUdB7ja6t0o4jhFYS0WsALyxUnxE9ePYJY5C-X3HCmr46hqpSYFVyJgNHsq7jVkDZ0E-TBvsKd49cYWputpWdwepSEbjK840HfEGUf0eRUtXDuWDsfDYEeGWD03qnirGBuqq6W4aNk31r6GgRTnB2UJ53cgGR0HC5EL2xdD2QhejHGwWt8WJrC6nsha-BHOcnYQ7U6hhhFJMJUBbncHMUX_wvbDy6aDuLgNLZx_kGRicoKoHEoU9_sy947LRjG4LqgiNnxHoTeBRt5AzvufyBrppZv1Twzvypca5YsrGDkut8efEjIi-vzFmk3z2Yh8AQ3kfQkvHZfC-g7mRXD7dLQIZrcoTz8yyN9hoD7bvQtcoMiEK7kOgh4vBO8WVek6Sj9UoRJ5KFMAELrklxT6DvnW82uZwVNkNOdpyoP169b50WmBkdrawnV9bsAU0poee8lhNWPN2NECiM4AHM4Q.PDPw2EpMW6smNgyqMjwvnA".to_string(),
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
