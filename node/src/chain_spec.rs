use crate::bitcoin::{
    btc_genesis_params, BtcGenesisParams, BtcParams, BtcTrusteeParams, Chain, TrusteeInfoConfig,
};
use frame_benchmarking::frame_support::PalletId;
use hex_literal::hex;
use sc_chain_spec::ChainSpecExtension;
use sc_service::config::TelemetryEndpoints;
use sc_service::{ChainType, Properties};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
pub use sherpax_runtime::{
    constants::currency::UNITS, opaque::SessionKeys, AccountId, AssetsBridgeConfig, AssetsConfig,
    AuraConfig, Balance, BalancesConfig, BaseFeeConfig, BlockNumber, DefaultBaseFeePerGas,
    EthereumChainIdConfig, EthereumConfig, EvmConfig, GenesisConfig, GrandpaConfig, SessionConfig,
    Signature, SudoConfig, SystemConfig, TechnicalMembershipConfig, VestingConfig, DAYS,
    WASM_BINARY,
};
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_core::crypto::UncheckedInto;
use sp_core::{sr25519, Pair, Public};
use sp_finality_grandpa::AuthorityId as GrandpaId;
use sp_runtime::traits::{AccountIdConversion, IdentifyAccount, Verify};
use std::{collections::BTreeMap, convert::TryInto};

// Note this is the URL for the telemetry server
const POLKADOT_TELEMETRY_URL: &str = "wss://telemetry.polkadot.io/submit/";
const CHAINX_TELEMETRY_URL: &str = "wss://telemetry.chainx.org/submit/";

const DEFAULT_PROTOCOL_ID: &str = "sherpax";

macro_rules! bootnodes {
    ( $( $bootnode:expr, )* ) => {
        vec![
            $($bootnode.to_string().try_into().expect("The bootnode is invalid"),)*
        ]
    }
}
/// Node `ChainSpec` extensions.
///
/// Additional parameters for some Substrate core modules,
/// customizable from the chain spec.
#[derive(Default, Clone, Serialize, Deserialize, ChainSpecExtension)]
#[serde(rename_all = "camelCase")]
pub struct Extensions {
    /// The light sync state.
    ///
    /// This value will be set by the `sync-state rpc` implementation.
    pub light_sync_state: sc_sync_state_rpc::LightSyncStateExtension,
}

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec<GenesisConfig, Extensions>;

/// Generate a crypto pair from seed.
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{}", seed), None)
        .expect("static values are valid; qed")
        .public()
}

type AccountPublic = <Signature as Verify>::Signer;

/// Generate an account ID from seed.
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
    AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
    AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

/// Generate an Aura authority key.
pub fn authority_keys_from_seed(s: &str) -> (AccountId, AuraId, GrandpaId) {
    (
        get_account_id_from_seed::<sr25519::Public>(s),
        get_from_seed::<AuraId>(s),
        get_from_seed::<GrandpaId>(s),
    )
}
type AssetId = u32;
type AssetName = Vec<u8>;
type AssetSymbol = Vec<u8>;
type AssetDecimals = u8;
type AssetSufficient = bool;
type AssetMinBalance = Balance;

/// Asset registration
fn sbtc() -> (Chain, AssetId) {
    (Chain::Bitcoin, 1)
}

/// Asset registration
fn doge() -> (Chain, AssetId) {
    (Chain::Dogecoin, 9)
}

#[allow(clippy::type_complexity)]
fn reserved_assets(
    root_key: &AccountId,
) -> (
    Vec<(AssetId, AccountId, AssetSufficient, AssetMinBalance)>,
    Vec<(AssetId, AssetName, AssetSymbol, AssetDecimals)>,
) {
    (
        vec![
            (0, root_key.clone(), true, 10_000_000_000u128),
            (1, root_key.clone(), true, 1u128),
            (2, root_key.clone(), true, 10_000_000_000u128),
            (3, root_key.clone(), true, 10_000_000_000u128),
            (4, root_key.clone(), true, 10_000_000_000u128),
            (5, root_key.clone(), true, 10_000_000_000u128),
            (6, root_key.clone(), true, 10_000_000_000u128),
            (7, root_key.clone(), true, 10_000_000_000u128),
            (8, root_key.clone(), true, 10_000_000_000u128),
            (9, root_key.clone(), true, 1u128),
        ],
        vec![
            (
                0,
                "Reserved0".to_string().into_bytes(),
                "RSV0".to_string().into_bytes(),
                18,
            ),
            (
                1,
                "SBTC".to_string().into_bytes(),
                "SBTC".to_string().into_bytes(),
                8,
            ),
            (
                2,
                "Reserved2".to_string().into_bytes(),
                "RSV2".to_string().into_bytes(),
                18,
            ),
            (
                3,
                "Reserved3".to_string().into_bytes(),
                "RSV3".to_string().into_bytes(),
                18,
            ),
            (
                4,
                "Reserved4".to_string().into_bytes(),
                "RSV4".to_string().into_bytes(),
                18,
            ),
            (
                5,
                "Reserved5".to_string().into_bytes(),
                "RSV5".to_string().into_bytes(),
                18,
            ),
            (
                6,
                "Reserved6".to_string().into_bytes(),
                "RSV6".to_string().into_bytes(),
                18,
            ),
            (
                7,
                "Reserved7".to_string().into_bytes(),
                "RSV7".to_string().into_bytes(),
                18,
            ),
            (
                8,
                "Reserved8".to_string().into_bytes(),
                "RSV8".to_string().into_bytes(),
                18,
            ),
            (
                9,
                "Dogecoin".to_string().into_bytes(),
                "Doge".to_string().into_bytes(),
                8,
            ),
        ],
    )
}

#[cfg(feature = "runtime-benchmarks")]
pub fn benchmarks_config() -> Result<ChainSpec, String> {
    let mut properties = Properties::new();
    properties.insert("tokenSymbol".into(), "KSX".into());
    properties.insert("tokenDecimals".into(), 18i32.into());
    properties.insert(
        "ss58Format".into(),
        sherpax_runtime::SS58Prefix::get().into(),
    );

    Ok(ChainSpec::from_genesis(
        "Benchmarks",
        "benchmarks",
        ChainType::Development,
        move || {
            let caller: AccountId = frame_benchmarking::whitelisted_caller();
            sherpax_genesis(
                // Initial PoA authorities
                vec![authority_keys_from_seed("Alice")],
                // Sudo account
                caller.clone(),
                // Pre-funded accounts
                vec![
                    get_account_id_from_seed::<sr25519::Public>("Alice"),
                    get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
                    caller.clone(),
                ],
                false,
                btc_genesis_params(include_str!(
                    "../res/genesis_config/gateway/btc_genesis_params_benchmarks.json"
                )),
                btc_genesis_params(include_str!(
                    "../res/genesis_config/gateway/dogecoin_genesis_params_testnet.json"
                )),
                crate::bitcoin::benchmarks_trustees(),
            )
        },
        // Bootnodes
        vec![],
        // Telemetry
        None,
        // Protocol ID
        None,
        // Properties
        None,
        Some(properties),
        // Extensions
        Default::default(),
    ))
}

pub fn development_config() -> Result<ChainSpec, String> {
    let mut properties = Properties::new();
    properties.insert("tokenSymbol".into(), "KSX".into());
    properties.insert("tokenDecimals".into(), 18i32.into());
    properties.insert(
        "ss58Format".into(),
        sherpax_runtime::SS58Prefix::get().into(),
    );

    Ok(ChainSpec::from_genesis(
        // Name
        "Development",
        // ID
        "dev",
        ChainType::Development,
        move || {
            sherpax_genesis(
                // Initial PoA authorities
                vec![authority_keys_from_seed("Alice")],
                // Sudo account
                get_account_id_from_seed::<sr25519::Public>("Alice"),
                // Pre-funded accounts
                vec![
                    get_account_id_from_seed::<sr25519::Public>("Alice"),
                    get_account_id_from_seed::<sr25519::Public>("Bob"),
                    get_account_id_from_seed::<sr25519::Public>("Charlie"),
                    get_account_id_from_seed::<sr25519::Public>("Dave"),
                    get_account_id_from_seed::<sr25519::Public>("Eve"),
                    get_account_id_from_seed::<sr25519::Public>("Ferdie"),
                ],
                false,
                btc_genesis_params(include_str!(
                    "../res/genesis_config/gateway/btc_genesis_params_testnet.json"
                )),
                btc_genesis_params(include_str!(
                    "../res/genesis_config/gateway/dogecoin_genesis_params_testnet.json"
                )),
                crate::bitcoin::dev_trustees(),
            )
        },
        // Bootnodes
        vec![],
        // Telemetry
        None,
        // Protocol ID
        None,
        None,
        // Properties
        Some(properties),
        // Extensions
        Default::default(),
    ))
}

pub fn local_testnet_config() -> Result<ChainSpec, String> {
    let mut properties = Properties::new();
    properties.insert("tokenSymbol".into(), "KSX".into());
    properties.insert("tokenDecimals".into(), 18i32.into());
    properties.insert(
        "ss58Format".into(),
        sherpax_runtime::SS58Prefix::get().into(),
    );

    Ok(ChainSpec::from_genesis(
        // Name
        "Local Testnet",
        // ID
        "local_testnet",
        ChainType::Local,
        move || {
            sherpax_genesis(
                // Initial PoA authorities
                vec![
                    authority_keys_from_seed("Alice"),
                    authority_keys_from_seed("Bob"),
                ],
                // Sudo account
                get_account_id_from_seed::<sr25519::Public>("Alice"),
                // Pre-funded accounts
                vec![
                    get_account_id_from_seed::<sr25519::Public>("Alice"),
                    get_account_id_from_seed::<sr25519::Public>("Bob"),
                    get_account_id_from_seed::<sr25519::Public>("Charlie"),
                    get_account_id_from_seed::<sr25519::Public>("Dave"),
                    get_account_id_from_seed::<sr25519::Public>("Eve"),
                    get_account_id_from_seed::<sr25519::Public>("Ferdie"),
                ],
                true,
                btc_genesis_params(include_str!(
                    "../res/genesis_config/gateway/btc_genesis_params_testnet.json"
                )),
                btc_genesis_params(include_str!(
                    "../res/genesis_config/gateway/dogecoin_genesis_params_testnet.json"
                )),
                crate::bitcoin::mainnet_trustees(),
            )
        },
        // Bootnodes
        vec![],
        // Telemetry
        None,
        // Protocol ID
        None,
        None,
        // Properties
        Some(properties),
        // Extensions
        Default::default(),
    ))
}

#[allow(unused)]
pub fn mainnet_config() -> Result<ChainSpec, String> {
    let bootnodes = bootnodes![
        "/ip4/52.77.243.26/tcp/10025/ws/p2p/12D3KooWK6zL4BFCFgcfCLn8xMmZcAp1wX6nTGfJx3gRzbq6qE3Y",
        "/ip4/47.114.74.52/tcp/40041/ws/p2p/12D3KooWJws7aM9euRhEM2CAvNTvKboiVi9wFRdHeWjtLUEiAJWo",
        "/ip4/116.62.46.8/tcp/40042/ws/p2p/12D3KooWSAeap3NaSihLuz85tX8uKn8f8Wfgo8iY9WFM1MRAvQiX",
    ];

    let mut properties = Properties::new();
    properties.insert("tokenSymbol".into(), "KSX".into());
    properties.insert("tokenDecimals".into(), 18i32.into());
    properties.insert(
        "ss58Format".into(),
        sherpax_runtime::SS58Prefix::get().into(),
    );

    Ok(ChainSpec::from_genesis(
        // Name
        "SherpaX",
        // ID
        "sherpax_singleton",
        ChainType::Live,
        move || {
            sherpax_genesis(
                // Initial PoA authorities
                vec![
                    (
                        // 5TYoist3MMKmUwJ7wDzY3wsHS8hqxeZUrjojzSpXJQrW99vz
                        hex!("acf61e664679fd0e71a644e38a7ebc16f90f31860f65640697ae2df395d25b41").into(),
                        hex!("d88a265ce7079a66d6bbe8975f0f1adf28165479a612a5b78496d411c27e2170").unchecked_into(),
                        hex!("ddacaccdc3a7bcd5c5bf65dda6347fea1fbe80fce049cf45cf07d7942288ca4a").unchecked_into(),
                    ),
                    (
                        // 5T6QnZixXittSYLytWVuucPPKZx5ex5UAzAmdM5CDZMFTXPJ
                        hex!("98d486fe9ca44c29edfd425b34dd437e94d9c3f66d0c708e2085954f29d85879").into(),
                        hex!("b83b4b675ccb164dd1010be607e0cb2132594532bb30d5fbcf95e3160941c74a").unchecked_into(),
                        hex!("55d1921b85e83e38ebcba4b01b574e5089674136e89d17fdb3243c15789fcb07").unchecked_into(),
                    ),
                    (
                        // 5S6UimBhL5NeqBhBUYywwNhNDFu3CHe8Soea3L8bmxuNHcN5
                        hex!("6ca589d347371b432cb16fb1d2aa188e95137d598535b2ec1be4c126cdc68412").into(),
                        hex!("2e45c8711cb703484143561aa1396e042a1bc9cd0f91eac52f89de5525702374").unchecked_into(),
                        hex!("09786f449c1e3450927cc3b6a333a72a604df488c21d6333512452b9ffdd3c48").unchecked_into(),
                    ),
                    (
                        // 5TwBtzUMZ47Qx17JqC1dWfaJVty7cMvwnup8JViH5RmWL7oF
                        hex!("be0829c9fddf9e393d97b3e2ab69fc2f43abc57f5628c3c67682ac6bffb39f58").into(),
                        hex!("a0033b24868202798bb486c1a84a85b926ba91080ec846ee4c6c7afb89fbc130").unchecked_into(),
                        hex!("ad0b31e886fa4594617719e075ef28e1332955cf32d689b6368f1a90c1bb836c").unchecked_into(),
                    ),
                ],
                // Sudo account
                // 5RgmPEzzbUW7Q4CDuUgETgKQ5WNMy6UgNsPXQNQq7rcCu8JV
                hex!("5a8fbe2953164bf17a6fdb565a2b829b8e16dac963ac90867b0cf9366fa0d70c").into(),
                // Pre-funded accounts
                vec![
                    hex!("5a8fbe2953164bf17a6fdb565a2b829b8e16dac963ac90867b0cf9366fa0d70c").into(),
                ],
                true,
                btc_genesis_params(include_str!(
                    "../res/genesis_config/gateway/btc_genesis_params_testnet.json"
                )),
                btc_genesis_params(include_str!(
                    "../res/genesis_config/gateway/dogecoin_genesis_params_mainnet.json"
                )),
                crate::bitcoin::mainnet_trustees(),
            )
        },
        // Bootnodes
        bootnodes,
        // Telemetry
        Some(
            TelemetryEndpoints::new(vec![
                (CHAINX_TELEMETRY_URL.to_string(), 0),
                (POLKADOT_TELEMETRY_URL.to_string(), 0),
            ])
            .expect("SherpaX telemetry url is valid; qed"),
        ),
        // Protocol ID
        Some(DEFAULT_PROTOCOL_ID),
        None,
        // Properties
        Some(properties),
        // Extensions
        Default::default(),
    ))
}

fn sherpax_session_keys(aura: AuraId, grandpa: GrandpaId) -> SessionKeys {
    SessionKeys { aura, grandpa }
}

fn technical_committee_membership() -> Vec<AccountId> {
    vec![
        // 5R3ce84HDRejpiMQV66vLt36393JknEA52kgTdKn6QJ6cuoV
        hex!["3e3a3ad45aa79cd22f5e104370269e210e659d9a271a8150ed7e99005da4c34e"].into(),
        // 5PybuwqSWcWEmqfNFoS8Tutc4mgYVTxPd9xMVQagUqE4kUHY
        hex!["0eee911c525dd47f6b40ca34bb524b9e70dea17fe0b32140d74fc503fdec8b07"].into(),
        // 5TNBbN7d3iGHFwT29kbKxtW5DEAFKQGzXjeDrdfZ485UYics
        hex!["a4dc0ab5e4d49632de1aec942ba30e8077f1a2480e8ca48cbdb775b4c2fa0e6f"].into(),
    ]
}

/// Configure initial storage state for FRAME modules.
pub fn sherpax_genesis(
    initial_authorities: Vec<(AccountId, AuraId, GrandpaId)>,
    root_key: AccountId,
    endowed_accounts: Vec<AccountId>,
    load_genesis: bool,
    bitcoin: BtcGenesisParams,
    dogecoin: BtcGenesisParams,
    trustees: Vec<(Chain, TrusteeInfoConfig, Vec<BtcTrusteeParams>)>,
) -> GenesisConfig {
    let (balances, vesting) = if load_genesis {
        load_genesis_config(&root_key)
    } else {
        let balances = endowed_accounts
            .iter()
            .cloned()
            .map(|k| (k, UNITS * 4096))
            .collect();

        (balances, Default::default())
    };

    let btc_genesis_trustees = trustees
        .iter()
        .find_map(|(chain, _, trustee_params)| {
            if *chain == Chain::Bitcoin {
                Some(
                    trustee_params
                        .iter()
                        .map(|i| (i.0).clone())
                        .collect::<Vec<_>>(),
                )
            } else {
                None
            }
        })
        .expect("bitcoin trustees generation can not fail; qed");
    let doge_genesis_trustees = trustees
        .iter()
        .find_map(|(chain, _, trustee_params)| {
            if *chain == Chain::Dogecoin {
                Some(
                    trustee_params
                        .iter()
                        .map(|i| (i.0).clone())
                        .collect::<Vec<_>>(),
                )
            } else {
                None
            }
        })
        .expect("dogecoin trustees generation can not fail; qed");
    let sbtc_info = sbtc();
    let doge_info = doge();
    let assets_info = reserved_assets(&root_key);
    let wasm_binary = WASM_BINARY.unwrap();
    GenesisConfig {
        system: SystemConfig {
            // Add Wasm runtime to storage.
            code: wasm_binary.to_vec(),
        },
        balances: BalancesConfig { balances },
        aura: Default::default(),
        grandpa: Default::default(),
        session: SessionConfig {
            keys: initial_authorities
                .iter()
                .map(|x| {
                    (
                        (x.0).clone(),
                        (x.0).clone(),
                        sherpax_session_keys(x.1.clone(), x.2.clone()),
                    )
                })
                .collect::<Vec<_>>(),
        },
        sudo: SudoConfig {
            // Assign network admin rights.
            key: Some(root_key),
        },
        vesting: VestingConfig { vesting },
        ethereum_chain_id: EthereumChainIdConfig { chain_id: 1506u64 },
        evm: Default::default(),
        ethereum: Default::default(),
        base_fee: BaseFeeConfig::new(
            DefaultBaseFeePerGas::get(),
            false,
            sp_runtime::Permill::from_parts(125_000),
        ),
        assets: sherpax_runtime::AssetsConfig {
            assets: assets_info.0,
            metadata: assets_info.1,
            accounts: vec![],
        },
        assets_bridge: AssetsBridgeConfig { admin_key: None },
        council: Default::default(),
        elections: Default::default(),
        democracy: Default::default(),
        technical_committee: Default::default(),
        technical_membership: TechnicalMembershipConfig {
            members: technical_committee_membership(),
            phantom: Default::default(),
        },
        treasury: Default::default(),
        x_gateway_common: sherpax_runtime::XGatewayCommonConfig {
            trustees,
            genesis_trustee_transition_status: false,
        },
        x_gateway_bitcoin: sherpax_runtime::XGatewayBitcoinConfig {
            genesis_trustees: btc_genesis_trustees,
            network_id: bitcoin.network,
            confirmation_number: bitcoin.confirmation_number,
            genesis_hash: bitcoin.hash(),
            genesis_info: (bitcoin.header(), bitcoin.height),
            params_info: BtcParams::new(
                // for signet and regtest
                545259519,            // max_bits
                2 * 60 * 60,          // block_max_future
                2 * 7 * 24 * 60 * 60, // target_timespan_seconds
                10 * 60,              // target_spacing_seconds
                4,                    // retargeting_factor
            ), // retargeting_factor
            btc_withdrawal_fee: 500000,
            max_withdrawal_count: 100,
        },
        x_gateway_dogecoin: sherpax_runtime::XGatewayDogecoinConfig {
            genesis_trustees: doge_genesis_trustees,
            network_id: dogecoin.network,
            confirmation_number: dogecoin.confirmation_number,
            genesis_hash: dogecoin.hash(),
            genesis_info: (dogecoin.header(), dogecoin.height),
            params_info: sherpax_runtime::DogeParams::new(
                // for dogecoin
                545259519,            // max_bits
                2 * 60 * 60,          // block_max_future
                2 * 7 * 24 * 60 * 60, // target_timespan_seconds
                10 * 60,              // target_spacing_seconds
                4,                    // retargeting_factor
            ), // retargeting_factor
            doge_withdrawal_fee: 500000,
            max_withdrawal_count: 100,
        },
        x_gateway_records: sherpax_runtime::XGatewayRecordsConfig {
            initial_asset_chain: vec![(sbtc_info.1, sbtc_info.0), (doge_info.1, doge_info.0)],
        },
    }
}

#[allow(clippy::type_complexity)]
fn load_genesis_config(
    root_key: &AccountId,
) -> (
    Vec<(AccountId, Balance)>,
    Vec<(AccountId, BlockNumber, BlockNumber, Balance)>,
) {
    let chainx_snapshot = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/res/genesis_config/balances/genesis_balances_chainx_snapshot_7418_7868415220855310000000000.json"
    ))
        .to_vec();

    let comingchat_miners = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/res/genesis_config/balances/genesis_balances_comingchat_miners_334721_2140742819000000000000000.json"
    ))
        .to_vec();

    let sherpax_contributors = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/res/genesis_config/balances/genesis_balances_sherpax_contributors_1873_94046984872650000000000.json"
    ))
        .to_vec();

    let vestings = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/res/genesis_config/vesting/genesis_vesting_342133_894769078020746000000000.json"
    ))
    .to_vec();

    let balances_configs: Vec<sherpax_runtime::BalancesConfig> = config_from_json_bytes(vec![
        chainx_snapshot,
        comingchat_miners,
        sherpax_contributors,
    ])
    .unwrap();

    let mut mutated_balances: Vec<(AccountId, u128)> = balances_configs
        .into_iter()
        .flat_map(|bc| bc.balances)
        .collect();

    // total transfer vesting balances
    let transfer_balances = 2631584779144690000000000u128;
    // 30000 ksx + transfer vesting balances
    let root_balance = 30000000000000000000000u128.saturating_add(transfer_balances);

    let back_to_treasury = 21000000000000000000000000u128
        .saturating_sub(root_balance)
        .saturating_sub(10103205024727960000000000u128);

    // 5S7WgdAXVK7mh8REvXfk9LdHs3Xqu9B2E9zzY8e4LE8Gg2ZX
    let treasury_account: AccountId = PalletId(*b"pcx/trsy").into_account();

    mutated_balances.push((root_key.clone(), root_balance));
    mutated_balances.push((treasury_account, back_to_treasury));

    let vesting_configs: Vec<sherpax_runtime::VestingConfig> =
        config_from_json_bytes(vec![vestings]).unwrap();

    let mut total_issuance: Balance = 0u128;
    let balances: Vec<(AccountId, u128)> = mutated_balances
        .into_iter()
        .fold(
            BTreeMap::<AccountId, Balance>::new(),
            |mut acc, (account_id, amount)| {
                if let Some(balance) = acc.get_mut(&account_id) {
                    *balance = balance
                        .checked_add(amount)
                        .expect("balance cannot overflow when building genesis");
                } else {
                    acc.insert(account_id.clone(), amount);
                }

                total_issuance = total_issuance
                    .checked_add(amount)
                    .expect("total insurance cannot overflow when building genesis");
                acc
            },
        )
        .into_iter()
        .collect();

    assert_eq!(
        balances.len(),
        342133 + 1 + 1 + 1873 - 35,
        "total accounts must be equal to 344013"
    );

    assert_eq!(
        total_issuance,
        21000000 * UNITS,
        "total issuance must be equal to 21000000000000000000000000"
    );

    let vestings: Vec<(AccountId, BlockNumber, BlockNumber, Balance)> = vesting_configs
        .into_iter()
        .flat_map(|vc| vc.vesting)
        .collect();
    let vesting_liquid = vestings.iter().map(|(_, _, _, free)| free).sum::<u128>();

    assert_eq!(
        vestings.len(),
        342133,
        "total vesting accounts must be equal 342138."
    );
    assert_eq!(
        vesting_liquid, 894769078020746000000000u128,
        "total vesting liquid must be equal 894769078020746000000000"
    );

    (balances, vestings)
}

fn config_from_json_bytes<T: DeserializeOwned>(bytes: Vec<Vec<u8>>) -> Result<Vec<T>, String> {
    let mut configs = vec![];

    for raw in bytes {
        let config = serde_json::from_slice(&raw)
            .map_err(|e| format!("Error parsing config file: {}", e))?;

        configs.push(config)
    }

    Ok(configs)
}
