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
        integrity_token: "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0.HkTWDZicvdcTUR6SsBqXcDXa5AdF2ji8AWd7uj7KCeK-ZjTy90n6jg.V_VLvzmCKC848mA6.EElce5eXzdI4j0T5u52UhIOQV5PhSn8jCrBFcGUhuCMS-3IzD2mZyFnBSmOiJCBjXrzSEPyRCeaNLtYlez8EObl1Of9rXuviYZu3c7y5ApAMgik4NvqnaqdqcdJ1FvqySiig5062LkmoVX40TTOLZjLJvzcLfHlX7zRKHwdbKT83fEBRqAA0qGu4ekYlqS2R71BRvFuzNy52M1xytm7oQz-PBfiDmQH9LJoYC1Dr0hP-eY3EJU7yIMzcrxzYOE9AteJkNMMVGGdF6IkRnoFaG8aXDE7azzg1ZBqLrfPQdWyqiVrAifdVEAVkBcnzh_DSdnabFMMyT2a4rNxntyY3tcycZEVELFPGYw_TnWQnA716OkQUvRu9A1ddyUJp-B5-zwT_9EDqAaLa2CLGYyucZSSD-lfHVLvb0e7FyBW0UVr089s0jHQajD3iugpCRZLsO4l5rRFpimdQ1UkGa4CmpphsjJeerF1bNq0NjlAh8dMW4wZ12Y1vSsjTvjEzggZBBXRwxORRetKEDkoJPIzT5QNLY88i2N-lXCC9ai-Ht4ZRTAC8uF_DQq0PT9Ot1T-RvOaXENR37fV48Zxwj6Z628m8V-e3VCjgAX3g5NDUt_K3di9jQuyTvGm4wAX7M3lZ_f_oY0eWYQ1YyVEcfcZCVlNMLFFJXv7-z9CICtKYgWpSmVcnHnEE1Ste1Fl3wVZYsRiG-oNcDzyqQC2cHpLVBT9p2uEjR-u0na8lhsZpuUNHESjKKlNcBj7NhbO9BGrsJFiNMjbH2DD9DawGr6GFemt4K_WVlGWF2vkXbNr_9qG4bTKN8PYDxfov3evzaIM8cTR8wm7QCtm16LdAJlc5UnFLJJYXLMNQLS66DW6atWN4AV1XxDPADl1-gfEk3zWjCarPsZ35F-2_3weCeT2s-dXnhubmAB5xeHZOYs5N0gqwbO9IrMqX70ZgnN3X3crqRBev3g3qlPrNj7a6K8iBibqzDUOGdKFsyaNtTDoOrlSu6-0XyTdmr_ZD4WgGhIH5RdVBG6D6ZOh4rE_C9hQu87vffpD1sTBAWjdgFD_VK-DZxB-1QifyysCy-SynOkOssd28VbySjJtPsl1u7zBp2Dgx6CkXZ1l2vGSj1Q2nvJlgGTJEa5SWKhu4HfJ807MbAAcIN1BLpDf8wRsxFX9C2h5pbvcHN-Vu4a_WV3xQT04Z1BKDPgo1x8pjO6vOfGKMHtke2ZlfWHRxnvrDs54DJDQkU_dAXJ0dQ1PdwNmPnnObCnhyUAGm4M5qlp8rNqTYbacvkaov.8mz-zEr2GXwSBJjujxeHXQ".to_string(),
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
