use std::error::Error;

use async_trait::async_trait;

use crate::workers::Worker;

pub struct ProvingWorker;

#[async_trait]
impl Worker for ProvingWorker {
    /// 1. Fetch all successful SNOS job runs that don't have a proving job
    /// 2. Create a proving job for each SNOS job run
    async fn run_worker(&self) -> Result<(), Box<dyn Error>> {
        todo!()
    }
}
