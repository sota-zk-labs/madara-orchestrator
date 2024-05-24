use crate::database::mongodb::config::MongoDbConfig;
use crate::database::mongodb::MongoDb;
use crate::database::{Database, DatabaseConfig, MockDatabase};
use crate::queue::sqs::SqsQueue;
use crate::queue::{MockQueueProvider, QueueProvider};
use crate::utils::env_utils::get_env_var_or_panic;
use color_eyre::Result;
use da_client_interface::DaConfig;
use da_client_interface::{DaClient, MockDaClient};
use dotenvy::dotenv;
use ethereum_da_client::config::EthereumDaConfig;
use ethereum_da_client::EthereumDaClient;
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Url};
use std::sync::Arc;
use tokio::sync::OnceCell;

/// The app config. It can be accessed from anywhere inside the service
/// by calling `config` function.
pub struct Config {
    /// The starknet client to get data from the node
    pub starknet_client: Arc<JsonRpcClient<HttpTransport>>,
    /// The DA client to interact with the DA layer
    pub da_client: Box<dyn DaClient>,
    /// The database client
    pub database: Box<dyn Database>,
    /// The queue provider
    pub queue: Box<dyn QueueProvider>,
}

/// Initializes the app config
pub async fn init_config() -> Config {
    dotenv().ok();

    // init starknet client
    let provider = JsonRpcClient::new(HttpTransport::new(
        Url::parse(get_env_var_or_panic("MADARA_RPC_URL").as_str()).expect("Failed to parse URL"),
    ));

    // init database
    let database = Box::new(MongoDb::new(MongoDbConfig::new_from_env()).await);

    // init the queue
    let queue = Box::new(SqsQueue {});

    Config { starknet_client: Arc::new(provider), da_client: build_da_client(), database, queue }
}

/// Initializes mock app config
#[cfg(test)]
pub async fn init_config_with_mocks(
    mock_database: MockDatabase,
    mock_queue_provider: MockQueueProvider,
    mock_da_client: MockDaClient,
    starknet_rpc_url: String,
) {
    dotenv().ok();

    // init starknet client
    let provider =
        JsonRpcClient::new(HttpTransport::new(Url::parse(starknet_rpc_url.as_str()).expect("Failed to parse URL")));

    let database = Box::new(mock_database);
    let queue = Box::new(mock_queue_provider);
    let da_client = Box::new(mock_da_client);

    let config = Config { starknet_client: Arc::new(provider), da_client, database, queue };
    assert!(CONFIG.set(config).is_ok());
}

impl Config {
    /// Returns the starknet client
    pub fn starknet_client(&self) -> &Arc<JsonRpcClient<HttpTransport>> {
        &self.starknet_client
    }

    /// Returns the DA client
    pub fn da_client(&self) -> &dyn DaClient {
        self.da_client.as_ref()
    }

    /// Returns the database client
    pub fn database(&self) -> &dyn Database {
        self.database.as_ref()
    }

    /// Returns the queue provider
    pub fn queue(&self) -> &dyn QueueProvider {
        self.queue.as_ref()
    }
}

/// The app config. It can be accessed from anywhere inside the service.
/// It's initialized only once.
pub static CONFIG: OnceCell<Config> = OnceCell::const_new();

/// Returns the app config. Initializes if not already done.
pub async fn config() -> &'static Config {
    CONFIG.get_or_init(init_config).await
}

/// Builds the DA client based on the environment variable DA_LAYER
fn build_da_client() -> Box<dyn DaClient + Send + Sync> {
    match get_env_var_or_panic("DA_LAYER").as_str() {
        "ethereum" => {
            let config = EthereumDaConfig::new_from_env();
            Box::new(EthereumDaClient::from(config))
        }
        _ => panic!("Unsupported DA layer"),
    }
}
