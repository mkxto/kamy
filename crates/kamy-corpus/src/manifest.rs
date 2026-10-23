//! Corpus member manifests (`meta.yml`) and the in-memory [`Member`] model.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

/// Oracle kind: how a member's observable behavior is captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberKind {
    Console,
    Gui,
    Dll,
}

/// A single exported symbol to invoke via the loader (dll members).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Export {
    pub name: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub ret: String,
}

/// Parsed `meta.yml` plus its resolved on-disk directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    /// Directory name (populated from the path, not the file).
    #[serde(skip)]
    pub name: String,
    /// Absolute member directory (`members/<name>` or `vendor/<name>`).
    #[serde(skip)]
    pub dir: PathBuf,
    pub kind: MemberKind,
    #[serde(default)]
    pub toolchain: Option<String>,
    #[serde(default)]
    pub lang: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub flags: Vec<String>,
    #[serde(default)]
    pub link_flags: Vec<String>,
    #[serde(default)]
    pub link_shim: bool,
    #[serde(default)]
    pub prebuilt: Option<String>,
    #[serde(default = "default_vectors")]
    pub vectors: u32,
    #[serde(default = "default_profile")]
    pub profile: String,
    #[serde(default)]
    pub exports: Vec<Export>,
    /// Named host exports which must be identity-lowered; empty selects all functions.
    #[serde(default)]
    pub lower_exports: Vec<String>,
    /// Optional exact process exit required by the original and protected oracle.
    #[serde(default)]
    pub expected_exit: Option<i32>,
}

fn default_vectors() -> u32 {
    1
}

fn default_profile() -> String {
    "no-transform".to_string()
}

impl Member {
    /// Output binary path blessed/built under the member dir.
    #[must_use]
    pub fn binary_path(&self) -> PathBuf {
        if let Some(prebuilt) = &self.prebuilt {
            return self.dir.join(prebuilt);
        }
        let ext = if self.kind == MemberKind::Dll {
            "dll"
        } else {
            "exe"
        };
        self.dir.join("orig").join(format!("{}.{ext}", self.name))
    }

    /// Path to this member's golden record.
    #[must_use]
    pub fn expected_path(&self) -> PathBuf {
        self.dir.join("expected.yml")
    }
}

fn load_member(meta_path: &Path) -> Result<Member> {
    let dir = meta_path
        .parent()
        .context("member meta.yml has no parent dir")?
        .to_path_buf();
    let name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .context("member dir has no name")?
        .to_string();
    let text = std::fs::read_to_string(meta_path)
        .with_context(|| format!("reading {}", meta_path.display()))?;
    let mut member: Member = serde_norway::from_str(&text)
        .with_context(|| format!("parsing {}", meta_path.display()))?;
    member.name = name;
    member.dir = dir;
    Ok(member)
}

fn collect_group(root: &Path, group: &str, out: &mut Vec<Member>) -> Result<()> {
    let group_dir = root.join(group);
    if !group_dir.is_dir() {
        return Ok(());
    }
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&group_dir)
        .with_context(|| format!("reading {}", group_dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    entries.sort();
    for dir in entries {
        let meta = dir.join("meta.yml");
        if meta.is_file() {
            out.push(load_member(&meta)?);
        }
    }
    Ok(())
}

/// Walk `members/*/meta.yml` and `vendor/*/meta.yml` under `dir`.
pub fn load_corpus(dir: &Path) -> Result<Vec<Member>> {
    let mut members = Vec::new();
    collect_group(dir, "members", &mut members)?;
    collect_group(dir, "vendor", &mut members)?;
    Ok(members)
}
