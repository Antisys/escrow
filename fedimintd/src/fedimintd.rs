use fedimint_core::fedimint_build_code_version_env;
use fedimint_escrow_server::EscrowInit;
use fedimintd::default_modules;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut modules = default_modules();
    modules.attach(EscrowInit);
    fedimintd::run(modules, fedimint_build_code_version_env!(), None).await?;
    unreachable!()
}
