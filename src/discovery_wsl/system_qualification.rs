//! Opt-in fixture driver; never part of the default agent's command surface.
use super::{Identity, native::token_identity, user_context};
use milvago_discovery_collector::{Budget, MAX_RESPONSE, system::Query};
use serde_json::Value;
use std::{io::Read, path::PathBuf, sync::atomic::AtomicBool, time::Duration};
use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::Threading::{GetCurrentProcess, GetProcessHandleCount, OpenProcessToken},
};

fn fixture() -> crate::Result<()> {
    let id = std::env::var("MILVAGO_DISCOVERY_WINDOWS_QA_ID")?;
    let parsed = uuid::Uuid::parse_str(&id)?;
    if parsed.is_nil() || parsed.to_string() != id {
        return Err("invalid system fixture identity".into());
    }
    let executable = std::env::current_exe()?;
    let expected =
        PathBuf::from(std::env::var_os("ProgramFiles").ok_or("program files unavailable")?)
            .join(format!("MilvagoWslQA-{id}"));
    if executable.parent() != Some(expected.as_path()) {
        return Err("owned installed fixture path required".into());
    }
    let directory = crate::cache_windows::Directory::installed(&expected)?;
    let _executable = directory.hold_file(executable.file_name().ok_or("missing executable")?)?;
    let mut marker = directory.hold_file(std::ffi::OsStr::new(&format!("{id}.txt")))?;
    let mut bytes = [0u8; 37];
    if marker.metadata()?.len() != 36
        || marker.read(&mut bytes)? != 36
        || &bytes[..36] != id.as_bytes()
    {
        return Err("owned fixture marker required".into());
    }
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut token) } == 0 {
        return Err("system token unavailable".into());
    }
    let sid = token_identity(token);
    unsafe { CloseHandle(token) };
    if sid? != "S-1-5-18" {
        return Err("fixture SYSTEM required".into());
    }
    session_zero()?;
    Ok(())
}

fn session_zero() -> crate::Result<()> {
    let mut session = u32::MAX;
    if unsafe {
        windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId(
            windows_sys::Win32::System::Threading::GetCurrentProcessId(),
            &mut session,
        )
    } == 0
        || session != 0
    {
        return Err("fixture service session zero required".into());
    }
    Ok(())
}

const HANDOFF_ID: &str = "11111111-1111-4111-8111-111111111111";

/// Fixture-only access to the production dispatcher, without enabling collection.
pub fn owner_inventory(budget: &Budget<'_>) -> crate::Result<Vec<u8>> {
    fixture()?;
    Ok(user_context::system_query(&Query::WslUserInventory, budget)
        .ok_or("fixture system dispatch missing")??)
}

/// The installed fixture embeds its own fixed observer entrypoint.
pub fn owner_observe(
    owner: &str,
    distribution: &str,
    input: &[u8],
    budget: &Budget<'_>,
) -> crate::Result<Vec<u8>> {
    fixture()?;
    Ok(user_context::observer_query(
        owner,
        distribution,
        input,
        budget,
    )?)
}

/// Exercise the actual cross-session channel without depending on a Linux guest.
/// The reserved fixture ID cannot qualify a real distribution or the COM transport.
pub fn handoff(owner: &str) -> crate::Result<()> {
    fixture()?;
    let query = || -> crate::Result<()> {
        let stop = AtomicBool::new(false);
        let budget = Budget::new(Duration::from_secs(8), &stop);
        let output = user_context::observer_query(owner, HANDOFF_ID, &vec![b'q'; 24576], &budget)?;
        if serde_json::from_slice::<Value>(&output)?
            != serde_json::json!({"owner_verified":true,"private_input":24576})
        {
            return Err("fixture cross-session input mismatch".into());
        }
        Ok(())
    };
    // WTS/RPC initialize process-wide resources on their first query. Measure
    // repeated transfers after that initialization, as the COM recipe does.
    query()?;
    let before = handles()?;
    for _ in 0..64 {
        query()?;
    }
    let after = handles()?;
    if after > before + 4 {
        return Err(format!("fixture cross-session handle growth: {before}->{after}").into());
    }
    Ok(())
}

pub fn handoff_probe() -> crate::Result<bool> {
    let raw = std::env::var("MILVAGO_GUEST_INPUT")?;
    if raw.len() > 1024 {
        return Err("fixture request limit".into());
    }
    let request: super::Request = serde_json::from_str(&raw)?;
    request.validate()?;
    let super::Request::Processes {
        owner_sid,
        distribution_id,
    } = request
    else {
        return Ok(false);
    };
    if distribution_id != HANDOFF_ID {
        return Ok(false);
    }
    if super::native::owner()? != owner_sid {
        return Err("fixture owner mismatch".into());
    }
    let input = super::input_section::receive(&std::env::var("MILVAGO_OBSERVER_INPUT")?)?;
    if input.as_slice() != &[b'q'; 24576] {
        return Err("fixture private input mismatch".into());
    }
    std::io::Write::write_all(
        &mut std::io::stdout(),
        b"{\"owner_verified\":true,\"private_input\":24576}",
    )?;
    Ok(true)
}

fn ask(query: Query) -> crate::Result<Value> {
    let stop = AtomicBool::new(false);
    let budget = Budget::new(Duration::from_secs(5), &stop);
    let bytes = user_context::system_query(&query, &budget).ok_or("system dispatch missing")??;
    if bytes.len() > MAX_RESPONSE {
        return Err("system fixture response limit".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn handles() -> crate::Result<u32> {
    let mut count = 0;
    if unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) } == 0 {
        return Err("fixture handle count unavailable".into());
    }
    Ok(count)
}

pub fn run() -> crate::Result<()> {
    fixture()?;
    let inventory = ask(Query::WslUserInventory)?;
    let rows = inventory.as_array().ok_or("invalid system inventory")?;
    if rows.len() != 2 {
        return Err("two owned synthetic distributions required".into());
    }
    let running = rows
        .iter()
        .find(|row| row["display_name"] == "milvago-qa-running")
        .ok_or("running fixture missing")?;
    let stopped = rows
        .iter()
        .find(|row| row["display_name"] == "milvago-qa-stopped")
        .ok_or("stopped fixture missing")?;
    if running["running"] != true || stopped["running"] != false {
        return Err("unexpected distribution state".into());
    }
    let live = Identity::parse(running["uuid"].as_str().ok_or("missing fixture identity")?)?;
    let idle = Identity::parse(stopped["uuid"].as_str().ok_or("missing fixture identity")?)?;
    if live.owner != idle.owner {
        return Err("unexpected fixture owners".into());
    }
    let query = || Query::WslGuest {
        owner_sid: live.owner.clone(),
        distribution_id: live.distribution.clone(),
    };
    let processes = ask(query())?;
    if processes["complete"] != true || processes["processes"].as_array().is_none() {
        return Err("incomplete fixture processes".into());
    }
    let observer = |identity: &Identity| -> crate::Result<serde_json::Value> {
        let stop = std::sync::atomic::AtomicBool::new(false);
        let budget =
            milvago_discovery_collector::Budget::new(std::time::Duration::from_secs(8), &stop);
        let output = super::user_context::observer_query(
            &identity.owner,
            &identity.distribution,
            &vec![b'q'; 24 * 1024],
            &budget,
        )?;
        Ok(serde_json::from_slice(&output)?)
    };
    if observer(&live)? != serde_json::json!({"uid":1000,"bytes":24576}) {
        return Err("default-user observer input mismatch".into());
    }
    if observer(&idle).is_ok() {
        return Err("observer started a stopped distribution".into());
    }
    let foreign = Identity {
        owner: "S-1-5-21-4294967295-4294967295-4294967295-4294967295".into(),
        distribution: live.distribution.clone(),
    };
    if observer(&foreign).is_ok() {
        return Err("observer accepted a foreign owner".into());
    }
    if ask(Query::WslGuest {
        owner_sid: idle.owner,
        distribution_id: idle.distribution,
    })
    .is_ok()
    {
        return Err("stopped guest process query unexpectedly succeeded".into());
    }
    if ask(Query::WslGuest {
        owner_sid: "S-1-5-21-4294967295-4294967295-4294967295-4294967295".into(),
        distribution_id: live.distribution.clone(),
    })
    .is_ok()
    {
        return Err("foreign owner query unexpectedly succeeded".into());
    }
    let before = handles()?;
    for _ in 0..8 {
        if observer(&live)? != serde_json::json!({"uid":1000,"bytes":24576}) {
            return Err("repeated observer input mismatch".into());
        }
        let rows = ask(Query::WslUserInventory)?;
        let rows = rows.as_array().ok_or("invalid repeated inventory")?;
        if rows
            .iter()
            .find(|row| row["display_name"] == "milvago-qa-stopped")
            .is_none_or(|row| row["running"] != false)
        {
            return Err("stopped distribution was started".into());
        }
    }
    if handles()? > before + 4 {
        return Err("system transport handle growth".into());
    }
    println!(
        "MILVAGO_WSL_SYSTEM_TRANSPORT=owner-token,inventory,processes,stopped-preserved,foreign-refused,handles"
    );
    println!(
        "MILVAGO_WSL_SYSTEM_OBSERVER=owner-token,linux-default-user,private-input,stopped-preserved,foreign-refused,handles"
    );
    println!("MILVAGO_WSL_SYSTEM_SESSION=0");
    Ok(())
}
