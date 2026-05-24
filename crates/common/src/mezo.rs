//! Mezo support helpers.
//!
//! Mezo's EVM exposes the native MEZO bank-module token at an ERC-20-like
//! address. Public RPC can answer `eth_call` against it, but local revm has no
//! Mezo native precompile provider. For debugger replay we mock the ERC-20
//! surface so transactions can still be traced locally.

use std::collections::HashMap;

use alloy_primitives::{address, b256, Address, Bytes, Log, B256, U256};
use revm::{
    context::ContextTr,
    context_interface::Cfg,
    interpreter::{CallInputs, CallOutcome, Gas, InstructionResult, InterpreterResult},
    Inspector,
};

/// Mezo testnet chain id.
pub const MEZO_TESTNET_CHAIN_ID: u64 = 31_611;
/// Public Mezo testnet JSON-RPC endpoint.
pub const MEZO_TESTNET_DEFAULT_RPC: &str = "https://rpc.test.mezo.org";
/// Mezo testnet native asset symbol.
pub const MEZO_TESTNET_NATIVE_SYMBOL: &str = "BTC";
/// Mezo testnet native asset decimals.
pub const MEZO_TESTNET_NATIVE_DECIMALS: u8 = 18;
/// Mezo mainnet chain id.
pub const MEZO_MAINNET_CHAIN_ID: u64 = 31_612;
/// Public Mezo mainnet JSON-RPC endpoint.
pub const MEZO_MAINNET_DEFAULT_RPC: &str = "https://mainnet.mezo.public.validationcloud.io";
/// Mezo mainnet native asset symbol.
pub const MEZO_MAINNET_NATIVE_SYMBOL: &str = "BTC";
/// Mezo mainnet native asset decimals.
pub const MEZO_MAINNET_NATIVE_DECIMALS: u8 = 18;
/// MEZO ERC-20 facade backed by the Cosmos bank module.
pub const MEZO_PRECOMPILE_ADDRESS: Address = address!("0x7B7c000000000000000000000000000000000001");

/// User-facing warning emitted whenever Mezo traces may include mocked native
/// precompile calls.
pub const MEZO_PRECOMPILE_WARNING: &str =
    "MEZO precompile mocked: native bank-module ERC-20 calls are synthetic in local revm replay";

/// User-facing warning for Mezo gas accounting.
pub const MEZO_GAS_WARNING: &str =
    "Mezo gas is approximate in local replay because Cosmos EVM gas refunds are configurable; state outputs remain reliable";

const SELECTOR_NAME: [u8; 4] = [0x06, 0xfd, 0xde, 0x03];
const SELECTOR_APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];
const SELECTOR_TOTAL_SUPPLY: [u8; 4] = [0x18, 0x16, 0x0d, 0xdd];
const SELECTOR_TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];
const SELECTOR_DECIMALS: [u8; 4] = [0x31, 0x3c, 0xe5, 0x67];
const SELECTOR_BALANCE_OF: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];
const SELECTOR_SYMBOL: [u8; 4] = [0x95, 0xd8, 0x9b, 0x41];
const SELECTOR_TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
const SELECTOR_ALLOWANCE: [u8; 4] = [0xdd, 0x62, 0xed, 0x3e];

// Start mocked accounts at U256::MAX / 2 instead of U256::MAX so simulated
// incoming MEZO transfers have headroom before clamping.
const MEZO_INITIAL_BALANCE: U256 = U256::from_limbs([u64::MAX, u64::MAX, u64::MAX, u64::MAX >> 1]);

const APPROVAL_TOPIC: B256 =
    b256!("0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925");
const TRANSFER_TOPIC: B256 =
    b256!("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");

/// True when `chain_id` is a supported Mezo network.
pub const fn is_mezo_chain(chain_id: u64) -> bool {
    chain_id == MEZO_TESTNET_CHAIN_ID || chain_id == MEZO_MAINNET_CHAIN_ID
}

/// True when an address is the MEZO ERC-20 facade.
pub fn is_mezo_precompile_address(address: Address) -> bool {
    address == MEZO_PRECOMPILE_ADDRESS
}

/// Return the configured default RPC URL for a chain when edb knows one.
pub const fn default_rpc_for_chain(chain_id: u64) -> Option<&'static str> {
    match chain_id {
        MEZO_TESTNET_CHAIN_ID => Some(MEZO_TESTNET_DEFAULT_RPC),
        MEZO_MAINNET_CHAIN_ID => Some(MEZO_MAINNET_DEFAULT_RPC),
        _ => None,
    }
}

/// Mock a call to Mezo's MEZO ERC-20 facade.
///
/// This intentionally avoids live RPC delegation: inspector callbacks are sync
/// and are used during multiple revm passes. The mock is optimistic so MEZO
/// reads and allowance checks do not block unrelated opcode-level debugging.
pub fn try_mock_mezo_precompile_call<CTX: ContextTr>(
    inspector: &mut MezoPrecompileMockInspector,
    context: &mut CTX,
    inputs: &mut CallInputs,
) -> Option<CallOutcome> {
    if !is_mezo_chain(context.cfg().chain_id()) {
        return None;
    }

    if !is_mezo_precompile_address(inputs.target_address)
        && !is_mezo_precompile_address(inputs.bytecode_address)
    {
        return None;
    }

    let calldata = inputs.input.bytes(context);
    let selector = calldata.get(..4).and_then(|selector| selector.try_into().ok());
    let native_decimals = match context.cfg().chain_id() {
        MEZO_MAINNET_CHAIN_ID => MEZO_MAINNET_NATIVE_DECIMALS,
        _ => MEZO_TESTNET_NATIVE_DECIMALS,
    };
    let output = inspector.mock_output(inputs.caller, native_decimals, selector, calldata.as_ref());

    let mut outcome = CallOutcome::new(
        InterpreterResult::new(
            InstructionResult::Return,
            output,
            gas_with_cost(inputs.gas_limit, selector.map_or(2_000, mock_gas_cost)),
        ),
        inputs.return_memory_offset.clone(),
    );

    if let Some(selector) = selector {
        if let Some(log) = mock_erc20_log(inputs.caller, selector, &calldata) {
            outcome.was_precompile_called = true;
            outcome.precompile_call_logs.push(log);
        }
    }

    Some(outcome)
}

/// Revm inspector that short-circuits Mezo's MEZO precompile facade.
#[derive(Debug, Default, Clone)]
pub struct MezoPrecompileMockInspector {
    balances: HashMap<Address, BalanceDelta>,
    allowances: HashMap<(Address, Address), U256>,
}

impl MezoPrecompileMockInspector {
    fn mock_output(
        &mut self,
        caller: Address,
        native_decimals: u8,
        selector: Option<[u8; 4]>,
        calldata: &[u8],
    ) -> Bytes {
        match selector {
            Some(SELECTOR_NAME) => encode_abi_string("MEZO"),
            Some(SELECTOR_SYMBOL) => encode_abi_string("MEZO"),
            Some(SELECTOR_DECIMALS) => encode_u256(U256::from(native_decimals)),
            Some(SELECTOR_TOTAL_SUPPLY) => encode_u256(U256::MAX),
            Some(SELECTOR_BALANCE_OF) => {
                let balance = decode_address_word(calldata, 4)
                    .map(|account| self.balance_of(account))
                    .unwrap_or(MEZO_INITIAL_BALANCE);
                encode_u256(balance)
            }
            Some(SELECTOR_ALLOWANCE) => {
                let allowance = decode_address_word(calldata, 4)
                    .zip(decode_address_word(calldata, 36))
                    .map(|(owner, spender)| self.allowance(owner, spender))
                    .unwrap_or(U256::MAX);
                encode_u256(allowance)
            }
            Some(SELECTOR_APPROVE) => {
                if let Some((spender, amount)) =
                    decode_address_word(calldata, 4).zip(decode_u256_word(calldata, 36))
                {
                    self.approve(caller, spender, amount);
                }
                encode_bool(true)
            }
            Some(SELECTOR_TRANSFER) => {
                if let Some((to, amount)) =
                    decode_address_word(calldata, 4).zip(decode_u256_word(calldata, 36))
                {
                    self.transfer(caller, to, amount);
                }
                encode_bool(true)
            }
            Some(SELECTOR_TRANSFER_FROM) => {
                if let Some(((from, to), amount)) = decode_address_word(calldata, 4)
                    .zip(decode_address_word(calldata, 36))
                    .zip(decode_u256_word(calldata, 68))
                {
                    self.transfer_from(caller, from, to, amount);
                }
                encode_bool(true)
            }
            _ => Bytes::new(),
        }
    }

    fn balance_of(&self, account: Address) -> U256 {
        let delta = self.balances.get(&account).copied().unwrap_or_default();
        MEZO_INITIAL_BALANCE.saturating_add(delta.credited).saturating_sub(delta.debited)
    }

    fn allowance(&self, owner: Address, spender: Address) -> U256 {
        // Default to zero so OZ SafeERC20 patterns work — `safeApprove`
        // and `forceApprove` require currentAllowance == 0 before
        // permitting a non-zero target. Real allowances become trackable
        // once a contract issues `approve(spender, value)` in-bundle.
        self.allowances.get(&(owner, spender)).copied().unwrap_or(U256::ZERO)
    }

    fn approve(&mut self, owner: Address, spender: Address, amount: U256) {
        self.allowances.insert((owner, spender), amount);
    }

    fn transfer(&mut self, from: Address, to: Address, amount: U256) {
        self.debit(from, amount);
        self.credit(to, amount);
    }

    fn transfer_from(&mut self, spender: Address, from: Address, to: Address, amount: U256) {
        self.transfer(from, to, amount);

        if let Some(allowance) = self.allowances.get_mut(&(from, spender)) {
            *allowance = allowance.saturating_sub(amount);
        }
    }

    fn debit(&mut self, account: Address, amount: U256) {
        let delta = self.balances.entry(account).or_default();
        delta.debited = delta.debited.saturating_add(amount);
    }

    fn credit(&mut self, account: Address, amount: U256) {
        let delta = self.balances.entry(account).or_default();
        delta.credited = delta.credited.saturating_add(amount);
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct BalanceDelta {
    credited: U256,
    debited: U256,
}

impl<CTX: ContextTr> Inspector<CTX> for MezoPrecompileMockInspector {
    fn call(&mut self, context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        try_mock_mezo_precompile_call(self, context, inputs)
    }
}

fn gas_with_cost(limit: u64, cost: u64) -> Gas {
    let mut gas = Gas::new(limit);
    let _ = gas.record_cost(cost.min(limit));
    gas
}

fn mock_gas_cost(selector: [u8; 4]) -> u64 {
    match selector {
        SELECTOR_NAME | SELECTOR_SYMBOL | SELECTOR_DECIMALS => 2_000,
        SELECTOR_TOTAL_SUPPLY | SELECTOR_BALANCE_OF | SELECTOR_ALLOWANCE => 2_600,
        SELECTOR_APPROVE | SELECTOR_TRANSFER | SELECTOR_TRANSFER_FROM => 8_000,
        _ => 2_000,
    }
}

fn encode_bool(value: bool) -> Bytes {
    encode_u256(U256::from(value as u8))
}

fn encode_u256(value: U256) -> Bytes {
    Bytes::from(value.to_be_bytes::<32>().to_vec())
}

fn encode_abi_string(value: &str) -> Bytes {
    let bytes = value.as_bytes();
    let padded_len = ((bytes.len() + 31) / 32) * 32;
    let mut output = Vec::with_capacity(64 + padded_len);
    output.extend_from_slice(&U256::from(32).to_be_bytes::<32>());
    output.extend_from_slice(&U256::from(bytes.len()).to_be_bytes::<32>());
    output.extend_from_slice(bytes);
    output.resize(64 + padded_len, 0);
    Bytes::from(output)
}

fn mock_erc20_log(caller: Address, selector: [u8; 4], calldata: &[u8]) -> Option<Log> {
    match selector {
        SELECTOR_APPROVE => {
            let spender = decode_address_word(calldata, 4)?;
            let amount = decode_word(calldata, 36)?;
            Some(Log::new_unchecked(
                MEZO_PRECOMPILE_ADDRESS,
                vec![APPROVAL_TOPIC, caller.into_word(), spender.into_word()],
                Bytes::from(amount.to_vec()),
            ))
        }
        SELECTOR_TRANSFER => {
            let to = decode_address_word(calldata, 4)?;
            let amount = decode_word(calldata, 36)?;
            Some(Log::new_unchecked(
                MEZO_PRECOMPILE_ADDRESS,
                vec![TRANSFER_TOPIC, caller.into_word(), to.into_word()],
                Bytes::from(amount.to_vec()),
            ))
        }
        SELECTOR_TRANSFER_FROM => {
            let from = decode_address_word(calldata, 4)?;
            let to = decode_address_word(calldata, 36)?;
            let amount = decode_word(calldata, 68)?;
            Some(Log::new_unchecked(
                MEZO_PRECOMPILE_ADDRESS,
                vec![TRANSFER_TOPIC, from.into_word(), to.into_word()],
                Bytes::from(amount.to_vec()),
            ))
        }
        _ => None,
    }
}

fn decode_address_word(calldata: &[u8], offset: usize) -> Option<Address> {
    let word = calldata.get(offset..offset + 32)?;
    Address::from_slice(word.get(12..32)?).into()
}

fn decode_word(calldata: &[u8], offset: usize) -> Option<[u8; 32]> {
    calldata.get(offset..offset + 32)?.try_into().ok()
}

fn decode_u256_word(calldata: &[u8], offset: usize) -> Option<U256> {
    decode_word(calldata, offset).map(U256::from_be_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_mezo_symbol() {
        let encoded = encode_abi_string("MEZO");
        assert_eq!(encoded.len(), 96);
        assert_eq!(&encoded[0..32], U256::from(32).to_be_bytes::<32>().as_slice());
        assert_eq!(&encoded[32..64], U256::from(4).to_be_bytes::<32>().as_slice());
        assert_eq!(&encoded[64..68], b"MEZO");
    }

    #[test]
    fn recognizes_mezo_chains() {
        assert!(is_mezo_chain(31_611));
        assert!(is_mezo_chain(31_612));
        assert_eq!(default_rpc_for_chain(31_611), Some(MEZO_TESTNET_DEFAULT_RPC));
        assert_eq!(default_rpc_for_chain(31_612), Some(MEZO_MAINNET_DEFAULT_RPC));
        assert!(!is_mezo_chain(1));
    }

    #[test]
    fn balance_of_returns_initial_balance_without_transfers() {
        let mut inspector = MezoPrecompileMockInspector::default();
        let account = address!("0x1111111111111111111111111111111111111111");

        assert_eq!(read_balance(&mut inspector, account), MEZO_INITIAL_BALANCE);
    }

    #[test]
    fn transfer_from_updates_sender_and_recipient_balances() {
        let mut inspector = MezoPrecompileMockInspector::default();
        let spender = address!("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
        let from = address!("0x1111111111111111111111111111111111111111");
        let to = address!("0x2222222222222222222222222222222222222222");

        call_mock(&mut inspector, spender, &transfer_from_calldata(from, to, U256::from(100)));

        assert_eq!(read_balance(&mut inspector, from), MEZO_INITIAL_BALANCE - U256::from(100));
        assert_eq!(read_balance(&mut inspector, to), MEZO_INITIAL_BALANCE + U256::from(100));
    }

    #[test]
    fn transfer_updates_caller_and_recipient_balances() {
        let mut inspector = MezoPrecompileMockInspector::default();
        let caller = address!("0x4444444444444444444444444444444444444444");
        let to = address!("0x3333333333333333333333333333333333333333");

        call_mock(&mut inspector, caller, &transfer_calldata(to, U256::from(50)));

        assert_eq!(read_balance(&mut inspector, caller), MEZO_INITIAL_BALANCE - U256::from(50));
        assert_eq!(read_balance(&mut inspector, to), MEZO_INITIAL_BALANCE + U256::from(50));
    }

    #[test]
    fn multiple_transfers_compose_balance_deltas() {
        let mut inspector = MezoPrecompileMockInspector::default();
        let a = address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let b = address!("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let c = address!("0xcccccccccccccccccccccccccccccccccccccccc");
        let d = address!("0xdddddddddddddddddddddddddddddddddddddddd");

        call_mock(&mut inspector, d, &transfer_from_calldata(a, b, U256::from(100)));
        call_mock(&mut inspector, d, &transfer_from_calldata(b, c, U256::from(25)));
        call_mock(&mut inspector, d, &transfer_calldata(a, U256::from(10)));

        assert_eq!(read_balance(&mut inspector, a), MEZO_INITIAL_BALANCE - U256::from(90));
        assert_eq!(read_balance(&mut inspector, b), MEZO_INITIAL_BALANCE + U256::from(75));
        assert_eq!(read_balance(&mut inspector, c), MEZO_INITIAL_BALANCE + U256::from(25));
        assert_eq!(read_balance(&mut inspector, d), MEZO_INITIAL_BALANCE - U256::from(10));
    }

    fn read_balance(inspector: &mut MezoPrecompileMockInspector, account: Address) -> U256 {
        let output = call_mock(inspector, Address::ZERO, &balance_of_calldata(account));
        decode_u256_word(output.as_ref(), 0).expect("balance output")
    }

    fn call_mock(
        inspector: &mut MezoPrecompileMockInspector,
        caller: Address,
        calldata: &[u8],
    ) -> Bytes {
        let selector = calldata.get(..4).and_then(|selector| selector.try_into().ok());
        inspector.mock_output(caller, MEZO_MAINNET_NATIVE_DECIMALS, selector, calldata)
    }

    fn transfer_calldata(to: Address, amount: U256) -> Vec<u8> {
        let mut calldata = SELECTOR_TRANSFER.to_vec();
        push_address_word(&mut calldata, to);
        push_u256_word(&mut calldata, amount);
        calldata
    }

    fn balance_of_calldata(account: Address) -> Vec<u8> {
        let mut calldata = SELECTOR_BALANCE_OF.to_vec();
        push_address_word(&mut calldata, account);
        calldata
    }

    fn transfer_from_calldata(from: Address, to: Address, amount: U256) -> Vec<u8> {
        let mut calldata = SELECTOR_TRANSFER_FROM.to_vec();
        push_address_word(&mut calldata, from);
        push_address_word(&mut calldata, to);
        push_u256_word(&mut calldata, amount);
        calldata
    }

    fn push_address_word(output: &mut Vec<u8>, address: Address) {
        output.extend_from_slice(&[0; 12]);
        output.extend_from_slice(address.as_slice());
    }

    fn push_u256_word(output: &mut Vec<u8>, value: U256) {
        output.extend_from_slice(&value.to_be_bytes::<32>());
    }
}
