use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{plugin_types_trait_impl_config, Amount};
use serde::{Deserialize, Serialize};

use crate::EscrowCommonInit;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowGenParams {
    pub local: EscrowGenParamsLocal,
    pub consensus: EscrowGenParamsConsensus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowGenParamsLocal;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowGenParamsConsensus {
    pub deposit_fee: Amount,
}

impl Default for EscrowGenParams {
    fn default() -> Self {
        Self {
            local: EscrowGenParamsLocal,
            consensus: EscrowGenParamsConsensus {
                deposit_fee: Amount::ZERO,
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EscrowConfig {
    pub private: EscrowConfigPrivate,
    pub consensus: EscrowConfigConsensus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable, Hash)]
pub struct EscrowClientConfig {
    pub deposit_fee: Amount,
}

#[derive(Clone, Debug, Serialize, Deserialize, Decodable, Encodable)]
pub struct EscrowConfigLocal;

#[derive(Clone, Debug, Serialize, Deserialize, Decodable, Encodable)]
pub struct EscrowConfigConsensus {
    pub deposit_fee: Amount,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EscrowConfigPrivate;

plugin_types_trait_impl_config!(
    EscrowCommonInit,
    EscrowConfig,
    EscrowConfigPrivate,
    EscrowConfigConsensus,
    EscrowClientConfig
);
