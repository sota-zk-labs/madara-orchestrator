use clap::Args;
/// Parameters used to config Aptos.
#[derive(Debug, Clone, Args)]
#[group(requires_all = ["da_on_aptos"])]
pub struct AptosDaCliArgs {
    /// Use the Aptos DA layer.
    #[arg(long)]
    pub da_on_aptos: bool,

    #[arg(env = "APTOS_NODE_URL", long)]
    pub da_aptos_node_url: Option<String>,

    #[arg(env = "APTOS_PRIVATE_KEY", long)]
    pub da_aptos_private_key: Option<String>,

    #[arg(env = "APTOS_MODULE_ADDRESS", long)]
    pub da_aptos_module_address: Option<String>,

    #[arg(env = "APTOS_CHAIN_ID", long)]
    pub da_aptos_chain_id: Option<String>,

    #[arg(env = "APTOS_TRUSTED_SETUP", long)]
    pub da_aptos_trusted_setup: Option<String>,
}
