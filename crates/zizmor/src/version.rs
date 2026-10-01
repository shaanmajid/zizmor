//! Build and version information for the zizmor CLI.

use std::fmt;

struct CommitInfo {
    short_commit_hash: &'static str,
    commit_date: &'static str,
    commits_since_last_tag: u32,
}

pub(crate) struct VersionInfo {
    version: &'static str,
    commit_info: Option<CommitInfo>,
    target_triple: &'static str,
}

impl fmt::Display for VersionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.version)?;

        if let Some(commit_info) = &self.commit_info {
            if commit_info.commits_since_last_tag > 0 {
                write!(f, "+{}", commit_info.commits_since_last_tag)?;
            }
            write!(
                f,
                " ({} {} {})",
                commit_info.short_commit_hash, commit_info.commit_date, self.target_triple
            )
        } else {
            write!(f, " ({})", self.target_triple)
        }
    }
}

impl From<VersionInfo> for clap::builder::Str {
    fn from(value: VersionInfo) -> Self {
        value.to_string().into()
    }
}

pub(crate) fn version() -> VersionInfo {
    let commit_info = option_env!("ZIZMOR_COMMIT_SHORT_HASH").and_then(|short_commit_hash| {
        Some(CommitInfo {
            short_commit_hash,
            commit_date: option_env!("ZIZMOR_COMMIT_DATE")?,
            commits_since_last_tag: option_env!("ZIZMOR_LAST_TAG_DISTANCE")
                .and_then(|distance| distance.parse().ok())
                .unwrap_or(0),
        })
    });

    VersionInfo {
        version: env!("CARGO_PKG_VERSION"),
        commit_info,
        target_triple: env!("RUST_HOST_TARGET"),
    }
}

#[cfg(test)]
mod tests {
    use super::{CommitInfo, VersionInfo};

    #[test]
    fn formats_version_without_commit_info() {
        assert_eq!(
            VersionInfo {
                version: "1.2.3",
                commit_info: None,
                target_triple: "aarch64-apple-darwin",
            }
            .to_string(),
            "1.2.3 (aarch64-apple-darwin)"
        );
    }

    #[test]
    fn formats_version_with_commit_info() {
        assert_eq!(
            VersionInfo {
                version: "1.2.3",
                commit_info: Some(CommitInfo {
                    short_commit_hash: "b7eb60271",
                    commit_date: "2026-09-13",
                    commits_since_last_tag: 4,
                }),
                target_triple: "aarch64-apple-darwin",
            }
            .to_string(),
            "1.2.3+4 (b7eb60271 2026-09-13 aarch64-apple-darwin)"
        );
    }
}
