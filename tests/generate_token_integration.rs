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
        integrity_token: "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0.qBn3SJsYtKyrSKTBc6g3ZXNy2UGtaKAaDDgOewdCHVG27eFVqP-bfA.hCt8jq8yU4aI1O2o.HIht2JDKyO-At_gfLxcTsU8GrlR-qMKtxGLXClyAJzQTtbl_Xfh0F6pYInVbe0bRcj4izcNjTfmgRbUapCNhvr-Ey07pSU6qYeNZ4yH3v_M1dLuM7UZ7zNR6A3LEixSz6SHzvn-7EPgO2xmsSrI3DfWAIc4hIqfAET9MvzalVGdLOhDDX3CGc1oWb1HL292tpqvs38SDkbSXLa4eu1WfSHc09AQ7P0zO_7HSvrKYQG_cft57FFZb_hp6hkEOFjXGR1QhNhMtc_lxRAuAiv3u9YNCVxXwotfjwtXZxmXwdBFbrbprR5enF1ZVHDC_hqaJitHVOWy_SoqJ2wAl4fHNmrLlsfwWmP2KdEQdISxVBQM-8-FLVO-sTtb2WMKMLQ743aObv270sraaAn81xJVtp7vkMK3ZmAh1qlnW5iHXJDd79a-KiPgVwkqIo-765kS23OH7eHapiyZLcXkpFniLMoXAuh_KrYWc1zXslQRNGFspv8Tt2DrOCRrOvf576HFZV9U1C01fssXbHMSQmsG6w5iB0pn_2rkuLpaVu36QrOQdF_xOgoSO-oPzguztCP_igsJ_g0HZmycnr09bXP7YpPq20-_ddfIE_84Yj-cnz_pzgyt3zQ_MYa7VoB6B8RrsW_moTpUuo_eSzs42rIbcMAjFYlHvRdhX2B5_fVd2vWbrJ9a8JZVY-yG81OaY43iEdF-iGsmQi4jbKevl91VROzjp_yh8f6o8W7YXxMi_gvJbww7CrBFgEjttq1jWstAkxke-1gUm8nAqMcglGXj8CI3hp023s3yougJjVh6C5qwptQzhLnNYrXkhlSgxZCFX4M4SSHqtSjnxwtcNET877rn5M2a6WtRp6H1kjLhEeBAy9KgC5hKCNiVSehChoJVZoU658TZgllRSJqvCp3c_W-XYdT2DSmXKY_3aeESoPAm76dxNt51vNtretJWkNvZOTrVeY1bFQRWnsHa-Iud0PAT7mIRoSBg12tUKuEg6vTeion1jguIihrM35Sn6l9zCYKm8wnxKO4WDRr6EKu86kmK4NFVZaA2H2nDC-zhA1PtAd7B-fHJd8xXQYFcxpLqt7cHs7DUPx48Zreacvdp0goW4upi0jDe92uAn7MUHxXYI9ylLFl5CaGTfu3EWL7xoSfEyHDGprPaGgEsBFYZ7L1UeI_oIcOhhA5l__0ltLOypmZ3GLcqQvwlleyrWhb-QaYwGaI63tcIqLmZ5U7Aua1nMC0iWWhuiWJRB5iCNv_P12My5tFzeWmTlQTme8EGUGympJxn8JcSLJ9cs7Dg.5lYpFww_ZZCgKcqAJf5iNw".to_string(),
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
