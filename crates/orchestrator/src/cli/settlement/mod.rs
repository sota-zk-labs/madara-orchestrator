use ethereum_settlement_client::EthereumSettlementValidatedArgs;
use starknet_settlement_client::StarknetSettlementValidatedArgs;
use aptos_settlement_client::AptosSettlementValidatedArgs;
pub mod ethereum;
pub mod starknet;
pub mod aptos;

#[derive(Clone, Debug)]
pub enum SettlementValidatedArgs {
    Ethereum(EthereumSettlementValidatedArgs),
    Starknet(StarknetSettlementValidatedArgs),
    Aptos(AptosSettlementValidatedArgs),
}
