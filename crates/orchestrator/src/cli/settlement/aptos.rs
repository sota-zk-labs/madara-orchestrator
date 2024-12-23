use clap::Args;

#[derive(Debug, Clone, Args)]
#[group(requires_all = ["aptos_node_url", "aptos_private_key", "aptos_module_address", "aptos_chain_id"])]
pub struct AptosSettlementCliArgs {
    #[arg(long)]
    pub settle_on_aptos: bool,

    #[arg(env = "APTOS_NODE_URL", long)]
    pub aptos_node_url: Option<String>,

    #[arg(env = "APTOS_PRIVATE_KEY", long)]
    pub aptos_private_key: Option<String>,

    #[arg(env = "APTOS_MODULE_ADDRESS", long)]
    pub aptos_module_address: Option<String>,

    #[arg(env = "APTOS_CHAIN_ID", long)]
    pub aptos_chain_id: Option<String>,
}