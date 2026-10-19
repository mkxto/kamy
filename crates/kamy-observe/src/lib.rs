//! Terminal-first structured logging for the kamy engine.
//!
//! One global `tracing` subscriber, installed once by the binary front-end.
//! Library crates emit plain `tracing` events/spans and stay unaware of how
//! they are rendered. Level and per-crate scope are driven by the `KAMY_LOG`
//! environment variable (standard `EnvFilter` syntax, e.g.
//! `KAMY_LOG=warn,kamy_link=debug,kamy_transforms=trace`) or by the front-end's
//! verbosity/`--log` flags. Diagnostics go to stderr so stdout stays reserved
//! for command results.

use std::io::IsTerminal as _;

use anyhow::Context as _;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, fmt};

/// Environment variable read for `EnvFilter` directives (the `RUST_LOG` analog).
pub const ENV_VAR: &str = "KAMY_LOG";

/// Terminal rendering flavor for log events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    /// One compact, colorized line per event with span scope. Robust under the
    /// per-function rayon parallelism; the default.
    #[default]
    Compact,
    /// Hierarchical span tree — nests each pipeline layer. Best for a
    /// single-threaded deep dive; worker threads interleave.
    Tree,
    /// Newline-delimited JSON for CI ingestion.
    Json,
}

impl std::str::FromStr for LogFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "compact" => Ok(Self::Compact),
            "tree" => Ok(Self::Tree),
            "json" => Ok(Self::Json),
            other => anyhow::bail!("unknown log format {other:?} (expected compact|tree|json)"),
        }
    }
}

/// Front-end logging request. `filter` (an explicit `EnvFilter` string) wins;
/// otherwise `KAMY_LOG`; otherwise a single level derived from
/// `quiet`/`verbosity`.
#[derive(Debug, Clone, Default)]
pub struct LogConfig {
    /// `-v` repeat count: 0 = info, 1 = debug, 2+ = trace.
    pub verbosity: u8,
    /// Errors only. Overrides `verbosity`.
    pub quiet: bool,
    /// Explicit `EnvFilter` directives (e.g. from `--log`). Highest priority.
    pub filter: Option<String>,
    pub format: LogFormat,
    /// `None` auto-detects a TTY on stderr.
    pub ansi: Option<bool>,
}

impl LogConfig {
    fn env_filter(&self) -> anyhow::Result<EnvFilter> {
        if let Some(directives) = self.filter.as_deref() {
            return EnvFilter::try_new(directives)
                .with_context(|| format!("invalid --log filter {directives:?}"));
        }
        if let Ok(env) = std::env::var(ENV_VAR) {
            if !env.trim().is_empty() {
                return EnvFilter::try_new(&env)
                    .with_context(|| format!("invalid {ENV_VAR} filter {env:?}"));
            }
        }
        let level = if self.quiet {
            LevelFilter::ERROR
        } else {
            match self.verbosity {
                0 => LevelFilter::INFO,
                1 => LevelFilter::DEBUG,
                _ => LevelFilter::TRACE,
            }
        };
        Ok(EnvFilter::default().add_directive(level.into()))
    }
}

/// Install the global subscriber. Fails if one is already set or the filter is
/// malformed; call exactly once at startup.
pub fn init(config: &LogConfig) -> anyhow::Result<()> {
    let ansi = config
        .ansi
        .unwrap_or_else(|| std::io::stderr().is_terminal());
    let registry = tracing_subscriber::registry().with(config.env_filter()?);
    match config.format {
        LogFormat::Compact => registry
            .with(
                fmt::layer()
                    .with_ansi(ansi)
                    .with_writer(std::io::stderr)
                    .compact(),
            )
            .try_init(),
        LogFormat::Json => registry
            .with(
                fmt::layer()
                    .with_ansi(ansi)
                    .with_writer(std::io::stderr)
                    .json(),
            )
            .try_init(),
        LogFormat::Tree => registry
            .with(
                tracing_tree::HierarchicalLayer::new(2)
                    .with_ansi(ansi)
                    .with_targets(true)
                    .with_writer(std::io::stderr),
            )
            .try_init(),
    }
    .map_err(|e| anyhow::anyhow!(e))
    .context("installing the global tracing subscriber")
}
