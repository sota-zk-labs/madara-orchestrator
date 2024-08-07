use std::collections::HashMap;

use crate::config::{config, config_force_init};
use crate::data_storage::MockDataStorage;
use da_client_interface::{DaVerificationStatus, MockDaClient};
use httpmock::prelude::*;
use rstest::*;
use serde_json::json;
use starknet_core::types::{FieldElement, MaybePendingStateUpdate, StateDiff, StateUpdate};
use uuid::Uuid;

use super::super::common::constants::{ETHEREUM_MAX_BLOB_PER_TXN, ETHEREUM_MAX_BYTES_PER_BLOB};
use super::super::common::{default_job_item, init_config};
use crate::jobs::da_job::DaJob;
use crate::jobs::types::{ExternalId, JobItem, JobStatus, JobType};
use crate::jobs::Job;

#[rstest]
#[tokio::test]
async fn test_create_job() {
    let config = init_config(None, None, None, None, None, None, None).await;
    let job = DaJob.create_job(&config, String::from("0"), HashMap::new()).await;
    assert!(job.is_ok());

    let job = job.unwrap();

    let job_type = job.job_type;
    assert_eq!(job_type, JobType::DataSubmission, "job_type should be DataSubmission");
    assert!(!(job.id.is_nil()), "id should not be nil");
    assert_eq!(job.status, JobStatus::Created, "status should be Created");
    assert_eq!(job.version, 0_i32, "version should be 0");
    assert_eq!(job.external_id.unwrap_string().unwrap(), String::new(), "external_id should be empty string");
}

#[rstest]
#[tokio::test]
async fn test_verify_job(#[from(default_job_item)] mut job_item: JobItem) {
    let mut da_client = MockDaClient::new();
    da_client.expect_verify_inclusion().times(1).returning(|_| Ok(DaVerificationStatus::Verified));

    let config = init_config(None, None, None, Some(da_client), None, None, None).await;
    assert!(DaJob.verify_job(&config, &mut job_item).await.is_ok());
}

#[rstest]
#[tokio::test]
async fn test_process_job() {
    let server = MockServer::start();

    let mut da_client = MockDaClient::new();
    let mut storage_client = MockDataStorage::new();
    let internal_id = "1";

    da_client.expect_max_bytes_per_blob().times(2).returning(move || ETHEREUM_MAX_BYTES_PER_BLOB);
    da_client.expect_max_blob_per_txn().times(1).returning(move || ETHEREUM_MAX_BLOB_PER_TXN);
    da_client.expect_publish_state_diff().times(1).returning(|_, _| Ok("0xbeef".to_string()));

    // Mocking storage client
    storage_client.expect_put_data().returning(|_, _| Ok(())).times(1);

    let config_init = init_config(
        Some(format!("http://localhost:{}", server.port())),
        None,
        None,
        Some(da_client),
        None,
        None,
        Some(storage_client),
    )
    .await;

    config_force_init(config_init).await;

    let state_update = MaybePendingStateUpdate::Update(StateUpdate {
        block_hash: FieldElement::default(),
        new_root: FieldElement::default(),
        old_root: FieldElement::default(),
        state_diff: StateDiff {
            storage_diffs: vec![],
            deprecated_declared_classes: vec![],
            declared_classes: vec![],
            deployed_contracts: vec![],
            replaced_classes: vec![],
            nonces: vec![],
        },
    });
    let state_update = serde_json::to_value(&state_update).unwrap();
    let response = json!({ "id": 1,"jsonrpc":"2.0","result": state_update });

    let state_update_mock = server.mock(|when, then| {
        when.path("/").body_contains("starknet_getStateUpdate");
        then.status(200).body(serde_json::to_vec(&response).unwrap());
    });

    assert_eq!(
        DaJob
            .process_job(
                config().await.as_ref(),
                &mut JobItem {
                    id: Uuid::default(),
                    internal_id: internal_id.to_string(),
                    job_type: JobType::DataSubmission,
                    status: JobStatus::Created,
                    external_id: ExternalId::String("1".to_string().into_boxed_str()),
                    metadata: HashMap::default(),
                    version: 0,
                }
            )
            .await
            .unwrap(),
        "0xbeef"
    );

    state_update_mock.assert();
}
