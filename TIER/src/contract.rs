#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    coin,
    coins,
    to_json_binary,
    BankMsg,
    Binary,
    Coin,
    CosmosMsg,
    Deps,
    DepsMut,
    Env,
    MessageInfo,
    Response,
    StdResult,
    SubMsg,
    Uint128,
    StakingQuery,
    AllDelegationsResponse,
};

use cosmwasm_std::DistributionMsg;
use cosmwasm_std::StakingMsg;

use crate::band::OraiPriceOracle;
use crate::error::ContractError;
use crate::msg::{
    ContractStatus,
    ExecuteMsg,
    ExecuteResponse,
    InstantiateMsg,
    QueryMsg,
    QueryResponse,
    ResponseStatus,
    SerializedWithdrawals,
};
use crate::state::{ self, Config, UserWithdrawal, CONFIG_ITEM, USER_INFOS, WITHDRAWALS_LIST };
use crate::utils;
use cosmwasm_std::StdError;

pub const UNBOUND_TIME: u64 = 21 * 24 * 60 * 60;
pub const ORAI: &str = "orai";

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg
) -> Result<Response, ContractError> {
    let deposits = msg.deposits
        .iter()
        .map(|v| v.u128())
        .collect::<Vec<_>>();

    if deposits.is_empty() {
        return Err(ContractError::Std(StdError::generic_err("Deposits array is empty")));
    }

    let is_sorted = deposits
        .as_slice()
        .windows(2)
        .all(|v| v[0] > v[1]);
    if !is_sorted {
        return Err(
            ContractError::Std(StdError::generic_err("Specify deposits in decreasing order"))
        );
    }

    let admin = msg.admin.unwrap_or("".to_string());
    let initial_config: Config = Config {
        status: ContractStatus::Active as u8,
        admin: admin,
        validators: msg.validators,
        usd_deposits: deposits,
        oraiswap_contract: msg.oraiswap_contract,
    };

    CONFIG_ITEM.save(deps.storage, &initial_config)?;
    // initial_config.save(&deps.storage)?;

    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg
) -> Result<Response, ContractError> {
    let response = match msg {
        ExecuteMsg::ChangeAdmin { admin, .. } => try_change_admin(deps, env, info, admin),
        ExecuteMsg::ChangeStatus { status, .. } => try_change_status(deps, env, info, status),
        ExecuteMsg::Deposit { .. } => try_deposit(deps, env, info),
        ExecuteMsg::Withdraw { .. } => try_withdraw(deps, env, info),
        ExecuteMsg::Claim { recipient, start, limit, .. } =>
            try_claim(deps, env, info, recipient, start, limit),
        ExecuteMsg::WithdrawRewards { recipient, .. } => {
            try_withdraw_rewards(deps, env, info, recipient)
        }
    };

    return response;
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => to_json_binary(&query_config(deps)?),
        QueryMsg::UserInfo { address } => to_json_binary(&query_user_info(deps, address)?),
        QueryMsg::Withdrawals { address, start, limit } =>
            to_json_binary(&query_withdrawals(deps, address, start, limit)?),
    }
}

pub fn try_change_admin(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    new_admin: String
) -> Result<Response, ContractError> {
    let config: Config = CONFIG_ITEM.load(deps.storage)?;
    if info.sender.clone() != config.admin {
        return Err(ContractError::Std(StdError::generic_err("Unauthorized")));
    }

    CONFIG_ITEM.update(
        deps.storage,
        |mut exists| -> StdResult<_> {
            exists.admin = new_admin;
            Ok(exists)
        }
    )?;

    Ok(Response::new().add_attribute("action", "changed admin"))
}

pub fn try_change_status(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    status: ContractStatus
) -> Result<Response, ContractError> {
    let config: Config = CONFIG_ITEM.load(deps.storage)?;
    if info.sender.clone() != config.admin {
        return Err(ContractError::Std(StdError::generic_err("Unauthorized")));
    }

    CONFIG_ITEM.update(
        deps.storage,
        |mut exists| -> StdResult<_> {
            exists.status = status as u8;
            Ok(exists)
        }
    )?;
    Ok(Response::new().add_attribute("action", "changed status"))
}

pub fn get_received_funds(_deps: &DepsMut, info: &MessageInfo) -> Result<Coin, ContractError> {
    match info.funds.get(0) {
        None => {
            return Err(ContractError::Std(StdError::generic_err("No Funds")));
        }
        Some(received) => {
            /* Amount of tokens received cannot be zero */
            if received.amount.is_zero() {
                return Err(ContractError::Std(StdError::generic_err("Not Allow Zero Amount")));
            }

            /* Allow to receive only token denomination defined
            on contract instantiation "config.stable_denom" */
            if received.denom.clone() != "orai" {
                return Err(ContractError::Std(StdError::generic_err("Unsopported token")));
            }

            /* Only one token can be received */
            if info.funds.len() > 1 {
                return Err(ContractError::Std(StdError::generic_err("Not Allowed Multiple Funds")));
            }
            Ok(received.clone())
        }
    }
}

pub fn try_deposit(deps: DepsMut, env: Env, info: MessageInfo) -> Result<Response, ContractError> {
    let config = CONFIG_ITEM.load(deps.storage)?;
    config.assert_contract_active()?;

    let sender = info.sender.to_string();

    let staked_amount = get_staked_amount(deps.as_ref(), &sender);

    let received_funds = get_received_funds(&deps, &info)?;

    let mut orai_deposit = received_funds.amount.u128();

    // Get Tier from staking amount

    let old_user_info = USER_INFOS.may_load(deps.storage, sender.clone())?.unwrap_or(
        state::UserInfo {
            ..Default::default()
        }
    );

    let total_usd_deposit = old_user_info.usd_deposit
        .checked_add(staked_amount.staked_usd_amount)
        .unwrap();
    let tier = config.tier_by_deposit(total_usd_deposit);

    let mut user_info = USER_INFOS.may_load(deps.storage, sender)?.unwrap_or(state::UserInfo {
        tier,
        ..Default::default()
    });
    //

    // Add already staked orai and last user's orai deposit
    orai_deposit = orai_deposit.checked_add(staked_amount.staked_orai_amount).unwrap();

    let orai_price_ocracle = OraiPriceOracle::new(&deps)?;

    let usd_deposit: u128 = orai_price_ocracle.usd_amount(orai_deposit);

    let current_tier = user_info.tier;
    let old_usd_deposit = user_info.usd_deposit;
    let new_usd_deposit = old_usd_deposit.checked_add(usd_deposit).unwrap();

    let new_tier = config.tier_by_deposit(new_usd_deposit);

    if current_tier == new_tier {
        if current_tier == config.max_tier() {
            return Err(ContractError::Std(StdError::generic_err("Reached max tier")));
        }

        let next_tier = current_tier.checked_sub(1).unwrap();
        let next_tier_deposit: u128 = config.deposit_by_tier(next_tier);

        let expected_deposit_usd = next_tier_deposit
            .checked_sub(old_usd_deposit + staked_amount.staked_usd_amount)
            .unwrap();
        let expected_deposit_orai = orai_price_ocracle.orai_amount(expected_deposit_usd);

        let err_msg = format!(
            "You should deposit at least {} USD ({} orai) for {}",
            expected_deposit_usd,
            expected_deposit_orai,
            orai_deposit
        );

        return Err(ContractError::Std(StdError::generic_err(&err_msg)));
    }

    let mut messages: Vec<SubMsg> = Vec::with_capacity(2);
    let new_tier_deposit = config.deposit_by_tier(new_tier);

    let orai_refund = orai_deposit
        .checked_sub(orai_price_ocracle.orai_amount(new_tier_deposit))
        .unwrap();

    if orai_refund != 0 {
        let send_msg = BankMsg::Send {
            to_address: info.sender.to_string(),
            amount: coins(orai_refund, ORAI),
        };

        let msg = CosmosMsg::Bank(send_msg);

        messages.push(SubMsg::new(msg));
    }
    let old_orai_deposit = user_info.orai_deposit;
    user_info.tier = new_tier;
    user_info.timestamp = env.block.time.seconds();
    user_info.orai_deposit = orai_price_ocracle
        .orai_amount(new_tier_deposit)
        .checked_sub(staked_amount.staked_orai_amount)
        .unwrap();
    user_info.usd_deposit = orai_price_ocracle.usd_amount(user_info.orai_deposit) + 1;
    USER_INFOS.save(deps.storage, info.sender.to_string(), &user_info)?;

    let validators = config.validators;

    for validator in validators {
        let individual_amount =
            ((user_info.orai_deposit - old_orai_deposit) * validator.clone().weight) / 100;
        let delegate_msg = StakingMsg::Delegate {
            validator: validator.address,
            amount: coin(individual_amount, ORAI),
        };

        let msg: CosmosMsg = CosmosMsg::Staking(delegate_msg);

        messages.push(SubMsg::new(msg));
    }

    let answer = to_json_binary(
        &(ExecuteResponse::Deposit {
            usd_deposit: Uint128::new(user_info.usd_deposit),
            orai_deposit: Uint128::new(user_info.orai_deposit),
            tier: new_tier,
            status: ResponseStatus::Success,
        })
    )?;

    Ok(Response::new().add_submessages(messages).set_data(answer))
}

pub fn try_withdraw(deps: DepsMut, env: Env, info: MessageInfo) -> Result<Response, ContractError> {
    let config = CONFIG_ITEM.load(deps.storage)?;
    config.assert_contract_active()?;

    let sender = info.sender.to_string();

    let min_tier = config.min_tier();
    let user_info = USER_INFOS.may_load(deps.storage, sender)?.unwrap_or(state::UserInfo {
        tier: min_tier,
        ..Default::default()
    });

    let amount = user_info.orai_deposit;

    USER_INFOS.remove(deps.storage, info.sender.to_string());

    let current_time = env.block.time.seconds();
    let claim_time = current_time.checked_add(UNBOUND_TIME).unwrap();
    let withdrawal = UserWithdrawal {
        amount,
        timestamp: current_time,
        claim_time,
    };

    let mut withdrawals = WITHDRAWALS_LIST.may_load(
        deps.storage,
        info.sender.to_string()
    )?.unwrap_or_default();

    withdrawals.push(withdrawal);
    WITHDRAWALS_LIST.save(deps.storage, info.sender.to_string(), &withdrawals)?;

    let validators = config.validators;
    let amount = coin(amount - 4, ORAI);

    let mut messages: Vec<SubMsg> = Vec::with_capacity(2);

    for validator in validators {
        let weight_as_uint128 = Uint128::from(validator.weight);

        // Perform the multiplication - Uint128 * Uint128
        let multiplied = amount.amount.multiply_ratio(weight_as_uint128, Uint128::from(100_u128));

        // Now, `multiplied` is Uint128, but we want the result as u128
        let individual_amount: u128 = multiplied.u128();

        let withdraw_msg = StakingMsg::Undelegate {
            validator: validator.address,
            amount: coin(individual_amount, ORAI),
        };
        let msg = CosmosMsg::Staking(withdraw_msg);
        messages.push(SubMsg::new(msg));
    }

    let answer = to_json_binary(
        &(ExecuteResponse::Withdraw {
            status: ResponseStatus::Success,
        })
    )?;

    Ok(Response::new().add_submessages(messages).set_data(answer))
}

pub fn try_claim(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    recipient: Option<String>,
    start: Option<u32>,
    limit: Option<u32>
) -> Result<Response, ContractError> {
    let config = CONFIG_ITEM.load(deps.storage)?;
    config.assert_contract_active()?;

    let sender = info.sender.to_string();
    let mut withdrawals = WITHDRAWALS_LIST.may_load(deps.storage, sender)?.unwrap_or_default();

    let length = withdrawals.len();

    if length == 0 {
        return Err(ContractError::Std(StdError::generic_err("Nothing to claim")));
    }

    let recipient = recipient.unwrap_or(info.sender.to_string());
    let start: usize = start.unwrap_or(0) as usize;
    let limit = limit.unwrap_or(50) as usize;
    let withdrawals_iter: std::iter::Take<
        std::iter::Skip<std::slice::Iter<'_, UserWithdrawal>>
    > = withdrawals.iter().skip(start).take(limit);

    let current_time = env.block.time.seconds();
    let mut remove_indices = Vec::new();
    let mut claim_amount = 0u128;

    for (index, withdrawal) in withdrawals_iter.enumerate() {
        let claim_time = withdrawal.claim_time;

        if current_time >= claim_time {
            remove_indices.push(index);
            claim_amount = claim_amount.checked_add(withdrawal.amount).unwrap();
        }
    }

    if claim_amount == 0 {
        return Err(ContractError::Std(StdError::generic_err("Nothing to claim")));
    }

    for (shift, index) in remove_indices.into_iter().enumerate() {
        let position = index.checked_sub(shift).unwrap();
        withdrawals.remove(position);
    }

    let send_msg = BankMsg::Send {
        to_address: recipient,
        amount: coins(claim_amount, ORAI),
    };

    let msg = CosmosMsg::Bank(send_msg);
    let answer = to_json_binary(
        &(ExecuteResponse::Claim {
            amount: claim_amount.into(),
            status: ResponseStatus::Success,
        })
    )?;

    Ok(Response::new().add_message(msg).set_data(answer))
}

pub fn try_withdraw_rewards(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    recipient: Option<String>
) -> Result<Response, ContractError> {
    let config: Config = CONFIG_ITEM.load(deps.storage)?;
    if info.sender.clone() != config.admin {
        return Err(ContractError::Std(StdError::generic_err("Unauthorized")));
    }

    let admin = config.admin;
    let recipient = recipient.unwrap_or(admin);
    let mut msgs: Vec<CosmosMsg> = Vec::new();
    let set_withdraw_addr_msg = DistributionMsg::SetWithdrawAddress { address: recipient };
    msgs.push(CosmosMsg::Distribution(set_withdraw_addr_msg));

    let mut total_withdraw_amount: u128 = 0;

    let validators = &config.validators;
    for validator_it in validators {
        let validator = validator_it.clone().address;
        let delegation = utils::query_delegation(&deps, &env, &validator);

        let can_withdraw = delegation
            .map(|d| d.unwrap().accumulated_rewards[0].amount.u128())
            .unwrap_or(0);

        let withdraw_msg = DistributionMsg::WithdrawDelegatorReward { validator };

        msgs.push(CosmosMsg::Distribution(withdraw_msg));

        total_withdraw_amount += can_withdraw;
    }

    if total_withdraw_amount == 0 {
        return Err(
            ContractError::Std(
                StdError::generic_err("There is nothing to withdraw from validators")
            )
        );
    }

    let answer = to_json_binary(
        &(ExecuteResponse::WithdrawRewards {
            amount: Uint128::new(total_withdraw_amount),
            status: ResponseStatus::Success,
        })
    )?;

    Ok(Response::new().add_messages(msgs).set_data(answer))
}

fn query_config(deps: Deps) -> StdResult<QueryResponse> {
    let config = CONFIG_ITEM.load(deps.storage)?;
    config.to_answer()
}

pub fn query_user_info(deps: Deps, address: String) -> StdResult<QueryResponse> {
    let config = CONFIG_ITEM.load(deps.storage)?;
    // Get Tier from staking amount
    let staked_amount = get_staked_amount(deps, &address);
    let old_user_info = USER_INFOS.may_load(deps.storage, address.clone())?.unwrap_or(
        state::UserInfo {
            ..Default::default()
        }
    );

    let total_usd_deposit = old_user_info.usd_deposit
        .checked_add(staked_amount.staked_usd_amount)
        .unwrap();
    let tier = config.tier_by_deposit(total_usd_deposit);

    let user_info = USER_INFOS.may_load(deps.storage, address)?.unwrap_or(state::UserInfo {
        tier,
        ..Default::default()
    });

    let answer = user_info.to_answer();
    return Ok(answer);
}

pub fn query_withdrawals(
    deps: Deps,
    address: String,
    start: Option<u32>,
    limit: Option<u32>
) -> StdResult<QueryResponse> {
    let withdrawals = WITHDRAWALS_LIST.may_load(deps.storage, address)?.unwrap_or_default();
    let amount = withdrawals.len();

    let start = start.unwrap_or(0);
    let limit = limit.unwrap_or(50);

    let mut serialized_withdrawals: Vec<SerializedWithdrawals> = Vec::new();
    for i in start..start + limit {
        let index: usize = i.try_into().unwrap();
        if index < amount {
            serialized_withdrawals.push(withdrawals[index].to_serialized());
        }
    }

    let answer = QueryResponse::Withdrawals {
        amount: amount.try_into().unwrap(),
        withdrawals: serialized_withdrawals,
    };

    Ok(answer)
}

pub struct StakedAmount {
    staked_usd_amount: u128,
    staked_orai_amount: u128,
}

pub fn get_staked_amount(deps: Deps, address: &str) -> StakedAmount {
    let delegation_query = (StakingQuery::AllDelegations {
        delegator: address.into(),
    }).into();

    // Since we don't own 'deps', we can still use reference to execute queries
    let all_delegations: AllDelegationsResponse = deps.querier.query(&delegation_query).unwrap();

    if all_delegations.delegations.is_empty() {
        return StakedAmount {
            staked_orai_amount: 0,
            staked_usd_amount: 0,
        };
    }

    let mut staked_amount_orai = Uint128::new(0);

    for delegation in all_delegations.delegations {
        staked_amount_orai += delegation.amount.amount;
    }

    let orai_price_oracle = OraiPriceOracle::deps_new(&deps).unwrap();

    let statked_usd_amount = orai_price_oracle.usd_amount(staked_amount_orai.into());

    return StakedAmount {
        staked_usd_amount: u128::from(statked_usd_amount),
        staked_orai_amount: staked_amount_orai.into(),
    };
}
