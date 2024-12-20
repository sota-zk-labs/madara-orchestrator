pub mod job_routes;
use std::io::Read;

use axum::http::StatusCode;
use bytes::Buf;
use reqwest::Client;
use rstest::*;

use crate::queue::init_consumers;
use crate::tests::config::{ConfigType, TestConfigBuilder};

#[rstest]
#[tokio::test]
async fn test_health_endpoint() {
    dotenvy::from_filename("../.env.test").expect("Failed to load the .env.test file");

    let services = TestConfigBuilder::new().configure_api_server(ConfigType::Actual).build().await;

    let addr = services.api_server_address.unwrap();

    let client = Client::new();
    let response = client
        .post(&format!("http://{}/health", addr))
        .send()
        .await
        .expect("Failed to send POST request");

    assert_eq!(response.status().as_str(), StatusCode::OK.as_str());

    let body = response.bytes().await.unwrap();
    let mut buf = String::new();
    let res = body.reader().read_to_string(&mut buf).unwrap();
    assert_eq!(res, 2);
}

#[rstest]
#[tokio::test]
async fn test_init_consumer() {
    let services = TestConfigBuilder::new().build().await;
    assert!(init_consumers(services.config).await.is_ok());
}
