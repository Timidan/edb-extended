//! Blockscout v2 source fetching utilities.

use std::{collections::BTreeMap, path::PathBuf};

use alloy_primitives::Address;
use alloy_transport_http::reqwest::{Client, StatusCode};
use eyre::{Context, Result};
use foundry_block_explorers::contract::Metadata as EtherscanMetadata;
use foundry_compilers::{
    artifacts::{output_selection::OutputSelection, CompilerOutput, SolcInput, Source, Sources},
    solc::SolcLanguage,
};
use semver::Version;
use serde::Deserialize;
use serde_json::Value;
use tracing::{debug, warn};

use crate::{find_or_install_solc, Artifact};

#[derive(Debug, Deserialize)]
struct BlockscoutAdditionalSource {
    file_path: Option<String>,
    source_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BlockscoutContractResponse {
    abi: Option<Value>,
    additional_sources: Option<Vec<BlockscoutAdditionalSource>>,
    compiler_settings: Option<Value>,
    compiler_version: Option<String>,
    constructor_args: Option<String>,
    evm_version: Option<String>,
    file_path: Option<String>,
    is_verified: Option<bool>,
    is_vyper_contract: Option<bool>,
    language: Option<String>,
    name: Option<String>,
    optimization_enabled: Option<bool>,
    optimization_runs: Option<u64>,
    source_code: Option<String>,
}

/// Try to fetch and compile a verified Solidity artifact from a Blockscout v2 API.
///
/// Returns `Ok(Some(Artifact))` if successful, `Ok(None)` for unverified or unsupported
/// contracts, and `Err` for malformed verified-source payloads or compilation failures.
pub async fn fetch_artifact_from_blockscout(
    api_base_url: &str,
    address: Address,
) -> Result<Option<Artifact>> {
    let addr_str = format!("{address:#x}");
    let url = format!("{}/smart-contracts/{addr_str}", api_base_url.trim_end_matches('/'));
    let client = Client::new();
    let response = client.get(&url).send().await.context("fetch blockscout contract")?;

    if response.status() == StatusCode::NOT_FOUND {
        debug!("blockscout contract not found for {addr_str}");
        return Ok(None);
    }

    if !response.status().is_success() {
        warn!("blockscout source fetch failed for {addr_str}: HTTP {}", response.status());
        return Ok(None);
    }

    let body: Value = response.json().await.context("parse blockscout contract response")?;
    if body.get("message").and_then(Value::as_str).is_some_and(|message| {
        message.eq_ignore_ascii_case("not found")
            || message.to_ascii_lowercase().contains("not verified")
    }) {
        debug!("blockscout returned non-source response for {addr_str}: {body}");
        return Ok(None);
    }

    let contract: BlockscoutContractResponse =
        serde_json::from_value(body).context("deserialize blockscout contract response")?;

    if contract.is_verified == Some(false) {
        debug!("blockscout contract is not verified for {addr_str}");
        return Ok(None);
    }

    if contract.is_vyper_contract == Some(true)
        || contract
            .language
            .as_deref()
            .is_some_and(|language| !language.eq_ignore_ascii_case("solidity"))
    {
        debug!("blockscout contract is not a Solidity source for {addr_str}");
        return Ok(None);
    }

    let source_code = contract.source_code.as_deref().unwrap_or_default().to_string();
    if source_code.trim().is_empty() {
        debug!("blockscout contract has no source code for {addr_str}");
        return Ok(None);
    }

    let contract_name = contract
        .name
        .as_deref()
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| eyre::eyre!("blockscout response missing contract name"))?;
    let compiler_version = contract
        .compiler_version
        .as_deref()
        .filter(|version| !version.trim().is_empty())
        .ok_or_else(|| eyre::eyre!("blockscout response missing compiler version"))?;
    let main_source_path = contract
        .file_path
        .as_deref()
        .filter(|path| !path.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{contract_name}.sol"));

    let mut source_entries = BTreeMap::new();
    source_entries.insert(main_source_path.clone(), source_code);

    for additional_source in contract.additional_sources.unwrap_or_default() {
        let Some(path) = additional_source.file_path.filter(|path| !path.trim().is_empty()) else {
            continue;
        };
        let Some(content) =
            additional_source.source_code.filter(|content| !content.trim().is_empty())
        else {
            continue;
        };
        source_entries.entry(path).or_insert(content);
    }

    let mut settings_value = normalize_compiler_settings(
        contract.compiler_settings,
        contract.optimization_enabled,
        contract.optimization_runs,
        contract.evm_version.as_deref(),
    );
    let mut settings: foundry_compilers::artifacts::Settings =
        serde_json::from_value(settings_value.clone())
            .context("parse blockscout compiler settings")?;
    settings.output_selection = OutputSelection::complete_output_selection();
    settings_value = serde_json::to_value(&settings).context("serialize normalized settings")?;

    let mut sources = Sources::new();
    let mut metadata_sources = serde_json::Map::new();
    for (path, content) in source_entries {
        sources.insert(PathBuf::from(&path), Source::new(content.clone()));
        metadata_sources.insert(path, serde_json::json!({ "content": content }));
    }

    let input = SolcInput::new(SolcLanguage::Solidity, sources, settings);

    let version = Version::parse(compiler_version.trim_start_matches('v'))?;
    let solc = find_or_install_solc(&version)?;
    let output: CompilerOutput = solc.compile_exact(&input)?;

    let abi_string = match contract.abi {
        Some(Value::String(abi)) => abi,
        Some(abi) => serde_json::to_string(&abi)?,
        None => "[]".to_string(),
    };
    let optimization_used = if contract.optimization_enabled.unwrap_or(false) { 1 } else { 0 };
    let optimization_runs = contract.optimization_runs.unwrap_or(200);
    let evm_version = contract
        .evm_version
        .as_deref()
        .filter(|version| !version.trim().is_empty())
        .unwrap_or("Default");
    let source_code_field = serde_json::json!({
        "language": "Solidity",
        "sources": metadata_sources,
        "settings": settings_value,
    });
    let synth = serde_json::json!({
        "Language": "Solidity",
        "CompilerVersion": compiler_version,
        "ContractName": contract_name,
        "SourceCode": source_code_field,
        "ABI": abi_string,
        "OptimizationUsed": optimization_used.to_string(),
        "Runs": optimization_runs,
        "ConstructorArguments": normalize_constructor_args(contract.constructor_args.as_deref()),
        "EVMVersion": evm_version,
        "Library": "",
        "LicenseType": "",
        "Proxy": "0",
        "Implementation": "",
        "SwarmSource": ""
    });
    let meta: EtherscanMetadata =
        serde_json::from_value(synth).context("synthesize blockscout metadata")?;

    Ok(Some(Artifact { meta, input, output }))
}

fn normalize_compiler_settings(
    compiler_settings: Option<Value>,
    optimization_enabled: Option<bool>,
    optimization_runs: Option<u64>,
    evm_version: Option<&str>,
) -> Value {
    let mut settings = compiler_settings.unwrap_or_else(|| serde_json::json!({}));
    if !settings.is_object() {
        settings = serde_json::json!({});
    }

    let settings_obj = settings.as_object_mut().expect("settings is object");

    let optimizer =
        settings_obj.entry("optimizer".to_string()).or_insert_with(|| serde_json::json!({}));
    if !optimizer.is_object() {
        *optimizer = serde_json::json!({});
    }
    let optimizer_obj = optimizer.as_object_mut().expect("optimizer is object");
    optimizer_obj
        .entry("enabled".to_string())
        .or_insert(Value::Bool(optimization_enabled.unwrap_or(false)));
    optimizer_obj
        .entry("runs".to_string())
        .or_insert_with(|| Value::from(optimization_runs.unwrap_or(200)));

    if settings_obj
        .get("evmVersion")
        .and_then(Value::as_str)
        .is_some_and(|version| version.eq_ignore_ascii_case("default"))
    {
        settings_obj.remove("evmVersion");
    }

    if let Some(evm_version) = evm_version
        .filter(|version| !version.trim().is_empty())
        .filter(|version| !version.eq_ignore_ascii_case("default"))
    {
        settings_obj.entry("evmVersion".to_string()).or_insert_with(|| Value::from(evm_version));
    }

    settings
}

fn normalize_constructor_args(constructor_args: Option<&str>) -> String {
    let Some(constructor_args) = constructor_args else {
        return String::new();
    };
    constructor_args
        .trim()
        .strip_prefix("0x")
        .unwrap_or_else(|| constructor_args.trim())
        .to_string()
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, str::FromStr};

    use serial_test::serial;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use super::*;

    const MUSD_ADDRESS: &str = "0x118917a40FAF1CD7a13dB0Ef56C86De7973Ac503";
    const MEZO_BLOCKSCOUT_API_BASE_URL: &str = "https://api.explorer.test.mezo.org/api/v2";

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn blockscout_fetches_multifile_contract_from_mock() -> Result<()> {
        let server = MockServer::start().await;
        let address = Address::from_str("0x0000000000000000000000000000000000001234")?;

        let response = serde_json::json!({
            "abi": [],
            "additional_sources": [
                {
                    "file_path": "contracts/Library.sol",
                    "source_code": "pragma solidity ^0.8.24; library Library { function value() internal pure returns (uint256) { return 7; } }"
                }
            ],
            "compiler_settings": {
                "evmVersion": "london",
                "optimizer": { "enabled": false, "runs": 200 },
                "metadata": { "useLiteralContent": true }
            },
            "compiler_version": "v0.8.24+commit.e11b9ed9",
            "constructor_args": null,
            "evm_version": "london",
            "file_path": "contracts/MockToken.sol",
            "is_verified": true,
            "is_vyper_contract": false,
            "language": "Solidity",
            "name": "MockToken",
            "optimization_enabled": false,
            "optimization_runs": 200,
            "source_code": "pragma solidity ^0.8.24; import './Library.sol'; contract MockToken { function value() external pure returns (uint256) { return Library.value(); } }"
        });

        Mock::given(method("GET"))
            .and(path(format!("/smart-contracts/{address:#x}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&server)
            .await;

        let artifact = fetch_artifact_from_blockscout(&server.uri(), address)
            .await?
            .expect("mock contract should compile");

        assert_eq!(artifact.contract_name(), "MockToken");
        assert!(artifact.contract().is_some());
        assert!(artifact.input.sources.contains_key(&PathBuf::from("contracts/MockToken.sol")));
        assert!(artifact.input.sources.contains_key(&PathBuf::from("contracts/Library.sol")));

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn blockscout_returns_none_for_unverified_mock() -> Result<()> {
        let server = MockServer::start().await;
        let address = Address::from_str("0x0000000000000000000000000000000000001235")?;

        Mock::given(method("GET"))
            .and(path(format!("/smart-contracts/{address:#x}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "is_verified": false,
                "message": "Contract source code not verified"
            })))
            .mount(&server)
            .await;

        let artifact = fetch_artifact_from_blockscout(&server.uri(), address).await?;
        assert!(artifact.is_none());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn blockscout_fetches_mezo_musd_live_when_enabled() -> Result<()> {
        if !matches!(std::env::var("EDB_MEZO_LIVE_TEST").as_deref(), Ok("1")) {
            eprintln!("skipping Mezo Blockscout live source fetch; set EDB_MEZO_LIVE_TEST=1");
            return Ok(());
        }

        let address = Address::from_str(MUSD_ADDRESS)?;
        let artifact = fetch_artifact_from_blockscout(MEZO_BLOCKSCOUT_API_BASE_URL, address)
            .await?
            .expect("MUSD should be verified on Mezo testnet Blockscout");

        let source_paths = artifact
            .input
            .sources
            .keys()
            .map(|path| path.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        eprintln!(
            "Mezo Blockscout source fetch: contract={} compiler={} sources={:?}",
            artifact.contract_name(),
            artifact.compiler_version(),
            source_paths
        );

        assert_eq!(artifact.contract_name(), "MUSD");
        assert!(artifact.contract().is_some());
        assert!(artifact.input.sources.contains_key(&PathBuf::from("contracts/token/MUSD.sol")));

        Ok(())
    }
}
