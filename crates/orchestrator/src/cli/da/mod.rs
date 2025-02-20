use aptos_da_client::AptosDaValidatedArgs;
use ethereum_da_client::EthereumDaValidatedArgs;

pub mod ethereum;
pub(crate) mod aptos;

#[derive(Debug, Clone)]
pub enum DaValidatedArgs {
    Ethereum(EthereumDaValidatedArgs),
    Aptos(AptosDaValidatedArgs),
}
