//! `kamy explain-reject`: report SSA-identity rejection status per function.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use super::parse_rva;

pub(crate) fn run(input: &Path, rva: Option<&str>) -> anyhow::Result<()> {
    let target = rva.map(parse_rva).transpose()?;

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = std::env::temp_dir().join(format!("kamy-explain-{}-{nonce}.bin", std::process::id()));

    let report = kamy_triage::protect_identity(input, &tmp, None);
    let _ = std::fs::remove_file(&tmp);
    let report = report?;

    match target {
        Some(r) => {
            if let Some((_, reason)) = report.rejected.iter().find(|(x, _)| *x == r) {
                println!("{r}  rejected: {}", reason.tag());
            } else if report.ssa_lowered_rvas.contains(&r) {
                println!("{r}  SSA-lowered");
            } else if report.moved.contains(&r) {
                println!("{r}  relocated verbatim");
            } else {
                println!("{r}  not found in report");
            }
        }
        None => {
            if report.rejected.is_empty() {
                println!("no rejections");
                return Ok(());
            }
            for (r, reason) in &report.rejected {
                println!("{r}  {}", reason.tag());
            }
            let mut by_reason: BTreeMap<&str, usize> = BTreeMap::new();
            for (_, reason) in &report.rejected {
                *by_reason.entry(reason.tag()).or_default() += 1;
            }
            println!("summary:");
            for (reason, count) in by_reason {
                println!("  {reason:<24} {count}");
            }
        }
    }
    Ok(())
}
