use agave_feature_set::{FeatureSet, FEATURE_NAMES};
use base64::{engine::general_purpose::STANDARD, Engine};
use litesvm::LiteSVM;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_account::Account;
use solana_address::Address;
use solana_clock::Clock;
use solana_epoch_rewards::EpochRewards;
use solana_epoch_schedule::EpochSchedule;
use solana_instruction::{AccountMeta, Instruction};
use solana_last_restart_slot::LastRestartSlot;
use solana_message::{Message, VersionedMessage};
use solana_rent::Rent;
use solana_signature::Signature;
use solana_slot_hashes::SlotHashes;
use solana_stake_interface::stake_history::StakeHistory;
use solana_transaction::versioned::VersionedTransaction;
use std::{collections::BTreeMap, env, fs, path::Path, str::FromStr};

type RunResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize)]
struct Fixture {
    schema_version: u8,
    program: Program,
    #[serde(default)]
    extra_programs: Vec<Program>,
    origin: Origin,
    payer: String,
    instruction: ReplayInstruction,
    #[serde(default)]
    transaction_base64: Option<String>,
    #[serde(default)]
    prelude_instructions: Vec<ReplayInstruction>,
    accounts: BTreeMap<String, Option<ReplayAccount>>,
    #[serde(default)]
    mutations: Vec<Mutation>,
    #[serde(default)]
    notes: Vec<String>,
}

#[derive(Deserialize, Serialize)]
struct Program {
    id: String,
    elf: String,
    sha256: String,
    #[serde(default)]
    loader: Option<String>,
    #[serde(default)]
    deployed_at_slot: Option<u64>,
    #[serde(default)]
    version_observed_slot: Option<u64>,
}

#[derive(Deserialize, Serialize)]
struct Origin {
    kind: String,
    #[serde(default)]
    replay_mode: Option<String>,
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    instruction_index: Option<usize>,
    #[serde(default)]
    inner_index: Option<usize>,
    #[serde(default)]
    transaction_slot: Option<u64>,
    #[serde(default)]
    execution_slot: Option<u64>,
    #[serde(default)]
    account_observed_slot: Option<u64>,
    #[serde(default)]
    state_exact: bool,
    #[serde(default)]
    program_version_verified: bool,
    #[serde(default)]
    signer_overrides: Vec<String>,
    #[serde(default)]
    route_context_sysvar_base64: Option<String>,
    #[serde(default)]
    clock_sysvar_base64: Option<String>,
    #[serde(default)]
    sysvars_base64: BTreeMap<String, String>,
    #[serde(default)]
    feature_activation_slots: Option<BTreeMap<String, u64>>,
}

#[derive(Deserialize)]
struct ReplayInstruction {
    program_id: String,
    accounts: Vec<ReplayMeta>,
    data_base64: String,
}

#[derive(Deserialize)]
struct ReplayMeta {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Deserialize)]
struct ReplayAccount {
    lamports: u64,
    owner: String,
    executable: bool,
    rent_epoch: u64,
    data_base64: String,
}

#[derive(Deserialize)]
struct Mutation {
    name: String,
    account: String,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    data_base64: Option<String>,
    #[serde(default)]
    lamports: Option<u64>,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    instruction_data_base64: Option<String>,
    #[serde(default)]
    signer_overrides: BTreeMap<String, bool>,
    #[serde(default)]
    instruction_account_override: BTreeMap<String, String>,
    #[serde(default)]
    clock_unix_timestamp: Option<i64>,
}

#[derive(Serialize, PartialEq)]
struct AccountState {
    lamports: u64,
    owner: String,
    executable: bool,
    rent_epoch: u64,
    data_len: usize,
    data_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_base64: Option<String>,
    spl_token_amount: Option<u64>,
}

#[derive(Serialize, PartialEq)]
struct AccountChange {
    before: Option<AccountState>,
    after: Option<AccountState>,
    effect: AccountEffect,
}

#[derive(Serialize, PartialEq, Clone)]
struct AccountEffect {
    lamports_delta: i128,
    spl_token_amount_delta: Option<i128>,
    other_data_xor_sha256: Option<String>,
    created_or_closed_data_sha256: Option<String>,
    owner_after: Option<String>,
    executable_after: Option<bool>,
    rent_epoch_after: Option<u64>,
    created: bool,
    closed: bool,
}

#[derive(Serialize)]
struct StepResult {
    index: usize,
    program_id: String,
    success: bool,
    error: Option<String>,
    compute_units: u64,
    logs: Vec<String>,
}

#[derive(Serialize)]
struct Scenario {
    name: String,
    success: bool,
    error: Option<String>,
    compute_units: u64,
    logs: Vec<String>,
    steps: Vec<StepResult>,
    changes: BTreeMap<String, AccountChange>,
}

#[derive(Serialize)]
struct Report {
    program: Program,
    origin: Origin,
    scenarios: Vec<Scenario>,
    changed_outcome: Vec<String>,
    limitations: Vec<String>,
}

fn address(value: &str) -> RunResult<Address> {
    Ok(Address::from_str(value)?)
}

fn decode(value: &str) -> RunResult<Vec<u8>> {
    Ok(STANDARD.decode(value)?)
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn state(account: Option<Account>, include_data: bool) -> Option<AccountState> {
    account.map(|account| AccountState {
        lamports: account.lamports,
        owner: account.owner.to_string(),
        executable: account.executable,
        rent_epoch: account.rent_epoch,
        data_len: account.data.len(),
        data_sha256: sha256(&account.data),
        data_base64: include_data.then(|| STANDARD.encode(&account.data)),
        spl_token_amount: token_amount(&account),
    })
}

fn token_amount(account: &Account) -> Option<u64> {
    let owner = account.owner.to_string();
    if account.data.len() < 165
        || (owner != "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
            && owner != "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
    {
        return None;
    }
    Some(u64::from_le_bytes(
        account.data[64..72].try_into().expect("token amount slice"),
    ))
}

fn effect(before: &Option<Account>, after: &Option<Account>) -> AccountEffect {
    let lamports_delta = after.as_ref().map_or(0, |a| a.lamports) as i128
        - before.as_ref().map_or(0, |a| a.lamports) as i128;
    let spl_token_amount_delta = match (
        before.as_ref().and_then(token_amount),
        after.as_ref().and_then(token_amount),
    ) {
        (Some(b), Some(a)) => Some(a as i128 - b as i128),
        _ => None,
    };
    let (other_data_xor_sha256, created_or_closed_data_sha256) = match (before, after) {
        (Some(b), Some(a)) if b.data.len() == a.data.len() => {
            let mut xor: Vec<u8> = b.data.iter().zip(&a.data).map(|(x, y)| x ^ y).collect();
            if spl_token_amount_delta.is_some() {
                xor[64..72].fill(0);
            }
            (xor.iter().any(|b| *b != 0).then(|| sha256(&xor)), None)
        }
        (Some(_), Some(a)) => (None, Some(sha256(&a.data))),
        (None, Some(a)) => (None, Some(sha256(&a.data))),
        (Some(b), None) => (None, Some(sha256(&b.data))),
        (None, None) => (None, None),
    };
    let owner_after = match (before, after) {
        (Some(b), Some(a)) if b.owner != a.owner => Some(a.owner.to_string()),
        _ => None,
    };
    let executable_after = match (before, after) {
        (Some(b), Some(a)) if b.executable != a.executable => Some(a.executable),
        _ => None,
    };
    let rent_epoch_after = match (before, after) {
        (Some(b), Some(a)) if b.rent_epoch != a.rent_epoch => Some(a.rent_epoch),
        _ => None,
    };
    AccountEffect {
        lamports_delta,
        spl_token_amount_delta,
        other_data_xor_sha256,
        created_or_closed_data_sha256,
        owner_after,
        executable_after,
        rent_epoch_after,
        created: before.is_none() && after.is_some(),
        closed: before.is_some() && after.is_none(),
    }
}

fn effect_signature(scenario: &Scenario) -> BTreeMap<String, AccountEffect> {
    scenario
        .changes
        .iter()
        .map(|(key, value)| (key.clone(), value.effect.clone()))
        .collect()
}

fn load_program(svm: &mut LiteSVM, program: &Program, base: &Path) -> RunResult<()> {
    let path = base.join(&program.elf);
    let bytes = fs::read(&path)?;
    let actual = sha256(&bytes);
    if actual != program.sha256 {
        return Err(format!(
            "{} SHA-256 mismatch: expected {}, got {}",
            path.display(),
            program.sha256,
            actual
        )
        .into());
    }
    if !bytes.starts_with(b"\x7fELF") {
        return Err(format!("{} is not an ELF", path.display()).into());
    }
    if let Some(loader) = &program.loader {
        svm.add_program_with_loader(address(&program.id)?, &bytes, address(loader)?)?;
    } else {
        svm.add_program(address(&program.id)?, &bytes)?;
    }
    Ok(())
}

fn replay_instruction(
    value: &ReplayInstruction,
    data_override: Option<&str>,
) -> RunResult<Instruction> {
    Ok(Instruction {
        program_id: address(&value.program_id)?,
        accounts: value
            .accounts
            .iter()
            .map(|meta| {
                Ok(AccountMeta {
                    pubkey: address(&meta.pubkey)?,
                    is_signer: meta.is_signer,
                    is_writable: meta.is_writable,
                })
            })
            .collect::<RunResult<Vec<_>>>()?,
        data: decode(data_override.unwrap_or(&value.data_base64))?,
    })
}

fn scenario(fixture: &Fixture, base: &Path, mutation: Option<&Mutation>) -> RunResult<Scenario> {
    let full_transaction = fixture.origin.replay_mode.as_deref() == Some("full_transaction");
    let mut svm = LiteSVM::new()
        .with_sigverify(false)
        .with_blockhash_check(!full_transaction)
        .with_transaction_history(0);
    if let Some(activation_slots) = &fixture.origin.feature_activation_slots {
        let mut features = FeatureSet::default();
        for (pubkey, activated_at) in activation_slots {
            features.activate(&address(pubkey)?, *activated_at);
        }
        svm = svm.with_feature_set(features);
    }
    if !full_transaction {
        if let Some(encoded) = &fixture.origin.route_context_sysvar_base64 {
            svm.set_instructions_sysvar_override(decode(encoded)?);
        }
    }
    if let Some(slot) = fixture
        .origin
        .execution_slot
        .or(fixture.origin.transaction_slot)
    {
        svm.warp_to_slot(slot);
        let mut clock = if let Some(encoded) = &fixture.origin.clock_sysvar_base64 {
            bincode::deserialize::<Clock>(&decode(encoded)?)?
        } else {
            svm.get_sysvar::<Clock>()
        };
        clock.slot = slot;
        svm.set_sysvar::<Clock>(&clock);
    }
    if let Some(unix_timestamp) = mutation.and_then(|m| m.clock_unix_timestamp) {
        let mut clock = svm.get_sysvar::<Clock>();
        clock.unix_timestamp = unix_timestamp;
        svm.set_sysvar(&clock);
    }
    for (name, encoded) in &fixture.origin.sysvars_base64 {
        let bytes = decode(encoded)?;
        match name.as_str() {
            "rent" => svm.set_sysvar(&bincode::deserialize::<Rent>(&bytes)?),
            "epoch_schedule" => svm.set_sysvar(&bincode::deserialize::<EpochSchedule>(&bytes)?),
            "last_restart_slot" => {
                svm.set_sysvar(&bincode::deserialize::<LastRestartSlot>(&bytes)?)
            }
            "epoch_rewards" => svm.set_sysvar(&bincode::deserialize::<EpochRewards>(&bytes)?),
            "slot_hashes" => svm.set_sysvar(&bincode::deserialize::<SlotHashes>(&bytes)?),
            "stake_history" => svm.set_sysvar(&bincode::deserialize::<StakeHistory>(&bytes)?),
            _ => return Err(format!("unsupported historical sysvar {name}").into()),
        }
    }
    load_program(&mut svm, &fixture.program, base)?;
    for extra in &fixture.extra_programs {
        load_program(&mut svm, extra, base)?;
    }
    let mut addresses = Vec::new();
    for (pubkey, input) in &fixture.accounts {
        let key = address(pubkey)?;
        if let Some(input) = input {
            if key == address(&fixture.program.id)?
                || fixture
                    .extra_programs
                    .iter()
                    .any(|p| address(&p.id).ok() == Some(key))
            {
                return Err(format!("{} is a loaded program; remove its snapshot", pubkey).into());
            }
            let mut data = decode(&input.data_base64)?;
            let mut lamports = input.lamports;
            let mut owner = input.owner.clone();
            if let Some(change) = mutation.filter(|m| m.account == *pubkey) {
                if let Some(replacement) = &change.owner {
                    owner = replacement.clone();
                }
                if let Some(replacement) = &change.data_base64 {
                    let offset = change.offset.unwrap_or(0);
                    let replacement = decode(replacement)?;
                    let end = offset
                        .checked_add(replacement.len())
                        .ok_or("mutation offset overflow")?;
                    if end > data.len() {
                        return Err(format!(
                            "mutation {} writes past {} bytes in {}",
                            change.name,
                            data.len(),
                            pubkey
                        )
                        .into());
                    }
                    data[offset..end].copy_from_slice(&replacement);
                }
                if let Some(value) = change.lamports {
                    lamports = value;
                }
            }
            svm.set_account(
                key,
                Account {
                    lamports,
                    data,
                    owner: address(&owner)?,
                    executable: input.executable,
                    rent_epoch: input.rent_epoch,
                },
            )?;
        } else if mutation.is_some_and(|m| m.account == *pubkey) {
            return Err(format!("cannot mutate absent account {}", pubkey).into());
        }
        addresses.push((pubkey.clone(), key));
    }
    let mut before = BTreeMap::new();
    for (label, key) in &addresses {
        before.insert(label.clone(), svm.get_account(key));
    }
    let payer = address(&fixture.payer)?;
    let mut ix = replay_instruction(
        &fixture.instruction,
        mutation.and_then(|m| m.instruction_data_base64.as_deref()),
    )?;
    if let Some(change) = mutation {
        if !change.signer_overrides.is_empty() && full_transaction {
            return Err("signer mutations require isolated instruction mode".into());
        }
        for (pubkey, is_signer) in &change.signer_overrides {
            let key = address(pubkey)?;
            let meta = ix
                .accounts
                .iter_mut()
                .find(|meta| meta.pubkey == key)
                .ok_or_else(|| {
                    format!("signer mutation account {pubkey} is not in the instruction")
                })?;
            meta.is_signer = *is_signer;
        }
        if !change.instruction_account_override.is_empty() && full_transaction {
            return Err("account substitution requires isolated instruction mode".into());
        }
        for (from, to) in &change.instruction_account_override {
            let from_key = address(from)?;
            let to_key = address(to)?;
            let meta = ix
                .accounts
                .iter_mut()
                .find(|meta| meta.pubkey == from_key)
                .ok_or_else(|| format!("override account {from} is not in the instruction"))?;
            meta.pubkey = to_key;
        }
    }
    let message = Message::new_with_blockhash(&[ix], Some(&payer), &svm.latest_blockhash());
    let tx = if full_transaction {
        let encoded = fixture
            .transaction_base64
            .as_ref()
            .ok_or("full transaction bytes missing")?;
        if mutation
            .and_then(|m| m.instruction_data_base64.as_ref())
            .is_some()
        {
            return Err(
                "instruction-data mutations are not supported in full-transaction mode".into(),
            );
        }
        bincode::deserialize::<VersionedTransaction>(&decode(encoded)?)?
    } else {
        VersionedTransaction {
            signatures: vec![Signature::default(); message.header.num_required_signatures as usize],
            message: VersionedMessage::Legacy(message),
        }
    };
    let mut steps = Vec::new();
    let mut all_logs = Vec::new();
    let mut total_compute_units = 0;
    let mut stopped_error = None;
    for (index, prelude) in fixture.prelude_instructions.iter().enumerate() {
        let ix = replay_instruction(prelude, None)?;
        let message = Message::new_with_blockhash(&[ix], Some(&payer), &svm.latest_blockhash());
        let prelude_tx = VersionedTransaction {
            signatures: vec![Signature::default(); message.header.num_required_signatures as usize],
            message: VersionedMessage::Legacy(message),
        };
        let (success, error, compute_units, logs) = match svm.send_transaction(prelude_tx) {
            Ok(meta) => (true, None, meta.compute_units_consumed, meta.logs),
            Err(failure) => (
                false,
                Some(format!("{:?}", failure.err)),
                failure.meta.compute_units_consumed,
                failure.meta.logs,
            ),
        };
        total_compute_units += compute_units;
        all_logs.extend(logs.clone());
        steps.push(StepResult {
            index,
            program_id: prelude.program_id.clone(),
            success,
            error: error.clone(),
            compute_units,
            logs,
        });
        if !success {
            stopped_error = error;
            break;
        }
    }
    let (success, error, compute_units, logs) = if let Some(error) = stopped_error {
        (
            false,
            Some(format!("prelude failed: {error}")),
            total_compute_units,
            all_logs,
        )
    } else {
        let index = steps.len();
        let (success, error, units, logs) = match svm.send_transaction(tx) {
            Ok(meta) => (true, None, meta.compute_units_consumed, meta.logs),
            Err(failure) => (
                false,
                Some(format!("{:?}", failure.err)),
                failure.meta.compute_units_consumed,
                failure.meta.logs,
            ),
        };
        total_compute_units += units;
        all_logs.extend(logs.clone());
        steps.push(StepResult {
            index,
            program_id: fixture.instruction.program_id.clone(),
            success,
            error: error.clone(),
            compute_units: units,
            logs,
        });
        (success, error, total_compute_units, all_logs)
    };
    let include_data = env::var_os("SOLDECOMP_INCLUDE_ACCOUNT_DATA").is_some();
    let mut changes = BTreeMap::new();
    for (label, key) in &addresses {
        let after = svm.get_account(key);
        let original = before.remove(label).expect("tracked account exists");
        if original != after {
            changes.insert(
                label.clone(),
                AccountChange {
                    before: state(original.clone(), include_data),
                    after: state(after.clone(), include_data),
                    effect: effect(&original, &after),
                },
            );
        }
    }
    Ok(Scenario {
        name: mutation.map_or("baseline".to_string(), |m| m.name.clone()),
        success,
        error,
        compute_units,
        logs,
        steps,
        changes,
    })
}

fn run(path: &Path) -> RunResult<Report> {
    let fixture: Fixture = serde_json::from_slice(&fs::read(path)?)?;
    if fixture.schema_version != 1 {
        return Err(format!("unsupported fixture schema {}", fixture.schema_version).into());
    }
    if fixture.instruction.program_id != fixture.program.id {
        return Err("instruction program ID does not match pinned ELF".into());
    }
    if !fixture.accounts.contains_key(&fixture.payer) {
        return Err("payer is missing from account snapshot".into());
    }
    for meta in &fixture.instruction.accounts {
        if !fixture.accounts.contains_key(&meta.pubkey) {
            return Err(format!(
                "instruction account {} is missing from snapshot",
                meta.pubkey
            )
            .into());
        }
    }
    for step in &fixture.prelude_instructions {
        for meta in &step.accounts {
            if !fixture.accounts.contains_key(&meta.pubkey) {
                return Err(format!("prelude account {} is missing", meta.pubkey).into());
            }
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for change in &fixture.mutations {
        if change.name == "baseline" || !seen.insert(&change.name) {
            return Err(format!("duplicate or reserved mutation name {}", change.name).into());
        }
        if change.account != "" && !fixture.accounts.contains_key(&change.account) {
            return Err(format!(
                "mutation {} account {} is missing",
                change.name, change.account
            )
            .into());
        }
        if change.data_base64.is_none()
            && change.lamports.is_none()
            && change.owner.is_none()
            && change.instruction_data_base64.is_none()
            && change.signer_overrides.is_empty()
            && change.instruction_account_override.is_empty()
            && change.clock_unix_timestamp.is_none()
        {
            return Err(format!("mutation {} changes nothing", change.name).into());
        }
    }
    let base = path.parent().unwrap_or(Path::new("."));
    let mut scenarios = vec![scenario(&fixture, base, None)?];
    for mutation in &fixture.mutations {
        scenarios.push(scenario(&fixture, base, Some(mutation))?);
    }
    let baseline = &scenarios[0];
    let baseline_effects = effect_signature(baseline);
    let changed_outcome = scenarios
        .iter()
        .skip(1)
        .filter(|s| {
            s.success != baseline.success
                || s.error != baseline.error
                || effect_signature(s) != baseline_effects
                || s.logs != baseline.logs
                || s.compute_units != baseline.compute_units
        })
        .map(|s| s.name.clone())
        .collect();
    let full_transaction = fixture.origin.replay_mode.as_deref() == Some("full_transaction");
    let mut limitations = vec!["Signature checks are disabled; signer flags are retained but original signatures are not verified.".to_string()];
    if !full_transaction {
        limitations.push("One target instruction is run in isolation; earlier instructions and transaction-wide context are not reproduced.".to_string());
    } else {
        limitations.push("The original outer transaction is replayed locally; historical runtime features, sysvars, and preceding same-slot writes may differ.".to_string());
    }
    if fixture.origin.route_context_sysvar_base64.is_some() && !full_transaction {
        limitations.push("The selected parent instruction was moved to index zero in the instructions sysvar; this preserves route data but not original instruction position.".to_string());
    }
    if !fixture.origin.state_exact {
        limitations.push("Account bytes are not proven to be the state immediately before the original transaction.".to_string());
    }
    if fixture.origin.transaction_slot.is_some() && !fixture.origin.program_version_verified {
        limitations.push(
            "Pinned ELF is not proven to be the program version at the original transaction slot."
                .to_string(),
        );
    }
    if fixture
        .origin
        .execution_slot
        .or(fixture.origin.transaction_slot)
        .is_some()
    {
        if fixture.origin.clock_sysvar_base64.is_some() {
            limitations.push("Archived Clock is restored; only sysvars present in the fixture are restored, and the local SVM version may still differ from the historical validator.".to_string());
        } else {
            limitations.push("Clock slot is set, but historical feature activation and other sysvars are not reconstructed.".to_string());
        }
    }
    limitations.extend(fixture.notes);
    Ok(Report {
        program: fixture.program,
        origin: fixture.origin,
        scenarios,
        changed_outcome,
        limitations,
    })
}

fn main() {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "--feature-ids" {
        let mut ids: Vec<String> = FEATURE_NAMES.keys().map(ToString::to_string).collect();
        ids.sort();
        println!(
            "{}",
            serde_json::to_string(&ids).expect("feature IDs serialization")
        );
        return;
    }
    let result = match args.as_slice() {
        [path] => run(Path::new(path)),
        _ => Err("usage: soldecomp-replay FIXTURE.json | --feature-ids".into()),
    };
    match result {
        Ok(report) => println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("report serialization")
        ),
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(2);
        }
    }
}
