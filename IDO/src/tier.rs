mod query {
    use crate::{ msg::{ ContractStatus, ValidatorWithWeight }, state::Config };
    use cosmwasm_std::{ StdError, StdResult, Uint128, Deps };
    use cw721::{ AllNftInfoResponse, TokensResponse, Cw721QueryMsg };
    use schemars::JsonSchema;
    use serde::{ Deserialize, Serialize };

    #[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
    pub struct Trait {
        pub trait_type: String,
        pub value: String,
    }

    #[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
    pub struct Metadata {
        pub attributes: Option<Vec<Trait>>,
    }

    // pub type Extension = Option<Metadata>;

    #[derive(Serialize)]
    #[serde(rename_all = "snake_case")]
    pub enum TierContractQuery {
        Config {},
        UserInfo {
            address: String,
        },
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum TierResponse {
        UserInfo {
            tier: u8,
        },
        Config {
            admin: String,
            validators: Vec<ValidatorWithWeight>,
            status: ContractStatus,
            usd_deposits: Vec<Uint128>,
            min_tier: u8,
        },
    }

    fn find_tier_in_metadata(metadata: Metadata) -> Option<u8> {
        let attrubutes = metadata.attributes.unwrap_or_default();

        for attribute in attrubutes {
            let trait_type = attribute.trait_type.to_lowercase();
            if trait_type != "id" {
                continue;
            }

            let tier = match attribute.value.as_str() {
                "XYZA" => 1,
                "XYZB" => 2,
                "XYZC" => 3,
                "XYZD" => 4,
                _ => 5,
            };
            return Some(tier);
        }

        Some(4)
    }

    pub fn get_tier_from_nft_contract(
        deps: &Deps,
        address: &String,
        config: &Config
    ) -> StdResult<Option<u8>> {
        let nft_contract = config.nft_contract.to_string();

        let msg = Cw721QueryMsg::Tokens { owner: address.clone(), start_after: None, limit: None };

        let tokensresponse: TokensResponse = deps.querier.query_wasm_smart(nft_contract, &msg)?;

        let token_list = tokensresponse.tokens.iter();
        let mut result_tier = 5;
        for token_id in token_list {
            let nft_contract = config.nft_contract.to_string();
            let msg = Cw721QueryMsg::AllNftInfo {
                token_id: token_id.clone(),
                include_expired: Some(false),
            };
            let nft_info: AllNftInfoResponse<Metadata> = deps.querier.query_wasm_smart(
                nft_contract,
                &msg
            )?;

            if nft_info.access.owner != address.to_string() {
                continue;
            }

            let public_metadata = nft_info.info;
            let tier = find_tier_in_metadata(public_metadata.extension);
            if let Some(tier) = tier {
                if tier < result_tier {
                    result_tier = tier;
                }
                continue;
            }
        }
        return Ok(Some(result_tier));
    }

    fn get_tier_from_tier_contract(deps: &Deps, address: String, config: &Config) -> StdResult<u8> {
        let tier_contract = config.tier_contract.to_string();
        let user_info = TierContractQuery::UserInfo { address };

        if
            let TierResponse::UserInfo { tier } = deps.querier.query_wasm_smart(
                tier_contract,
                &user_info
            )?
        {
            Ok(tier)
        } else {
            Err(StdError::generic_err("Cannot get tier"))
        }
    }

    pub fn get_tier(deps: &Deps, address: String) -> StdResult<u8> {
        let config = Config::load(deps.storage)?;

        let from_nft_contract = get_tier_from_nft_contract(deps, &address, &config)?;

        let mut tier = get_tier_from_tier_contract(deps, address, &config)?;
        if let Some(nft_tier) = from_nft_contract {
            if nft_tier < tier {
                tier = nft_tier;
            }
        }

        Ok(tier)
    }

    pub fn get_min_tier(deps: &Deps, config: &Config) -> StdResult<u8> {
        let tier_contract = config.tier_contract.to_string();
        let user_info = TierContractQuery::Config {};

        if
            let TierResponse::Config { min_tier, .. } = deps.querier.query_wasm_smart(
                tier_contract,
                &user_info
            )?
        {
            Ok(min_tier)
        } else {
            Err(StdError::generic_err("Cannot get min tier"))
        }
    }
}

#[cfg(test)]
pub mod manual {
    use crate::state::Config;
    use cosmwasm_std::{ StdResult, Deps };
    use std::sync::Mutex;

    static TIER: Mutex<u8> = Mutex::new(0);
    static MIN_TIER: Mutex<u8> = Mutex::new(4);

    pub fn set_tier(tier: u8) {
        let mut tier_lock = TIER.lock().unwrap();
        *tier_lock = tier;
    }

    pub fn set_min_tier(tier: u8) {
        let mut tier_lock = MIN_TIER.lock().unwrap();
        *tier_lock = tier;
    }

    pub fn get_tier(_deps: &Deps, _address: String) -> StdResult<u8> {
        let tier_lock = TIER.lock().unwrap();
        Ok(*tier_lock)
    }

    pub fn get_min_tier(_deps: &Deps, _config: &Config) -> StdResult<u8> {
        let tier_lock = MIN_TIER.lock().unwrap();
        Ok(*tier_lock)
    }

    pub fn get_tier_from_nft_contract(
        _deps: &Deps,
        _address: &String,
        _config: &Config
    ) -> StdResult<Option<u8>> {
        let tier_lock = TIER.lock().unwrap();
        Ok(Some(*tier_lock))
    }
}

#[cfg(not(test))]
pub use query::get_tier;

#[cfg(not(test))]
pub use query::get_min_tier;

#[cfg(not(test))]
pub use query::get_tier_from_nft_contract;

#[cfg(test)]
pub use manual::get_tier;

#[cfg(test)]
pub use manual::get_min_tier;

#[cfg(test)]
pub use manual::get_tier_from_nft_contract;
