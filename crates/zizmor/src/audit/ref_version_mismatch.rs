use anyhow::anyhow;
use github_actions_models::common::Uses;
use subfeature::Subfeature;
use yamlpatch::{Op, Patch};

use crate::{
    audit::{Audit, AuditError, AuditLoadError, AuditState, audit_meta},
    finding::{
        Confidence, Finding, Fix, Persona, Severity,
        location::{Comment, Feature, Locatable, Location, Routable as _},
    },
    github,
    models::{
        AsDocument, StepCommon,
        action::CompositeStep,
        pre_commit,
        repo_ref::RepoRef,
        version::RawVersion,
        workflow::{ReusableWorkflowCallJob, Step},
    },
    utils::once::debug_once,
};

pub(crate) struct RefVersionMismatch {
    client: github::Client,
}

audit_meta!(
    RefVersionMismatch,
    "ref-version-mismatch",
    "action's hash pin has mismatched or missing version comment"
);

/// The YAML key that holds a pinned ref.
///
/// This also determines the style of version comment we produce in fixes.
#[derive(Clone, Copy)]
enum RefKey {
    /// A `uses:` clause in a workflow or action.
    Uses,
    /// A `rev:` in a pre-commit config.
    Rev,
}

impl RefKey {
    fn as_str(self) -> &'static str {
        match self {
            Self::Uses => "uses",
            Self::Rev => "rev",
        }
    }

    /// The version comment to add when none is present.
    ///
    /// For pre-commit, this matches what `autoupdate --freeze` writes.
    fn new_comment(self, tag: &str) -> String {
        match self {
            Self::Uses => format!("# {tag}"),
            Self::Rev => format!("# frozen: {tag}"),
        }
    }

    /// The version comment to replace a mismatched one with.
    ///
    /// For pre-commit, this preserves the existing comment's style
    /// (e.g. `# frozen: vX` or `# vX`) by replacing only the version.
    fn updated_comment(self, comment: &str, version: &str, tag: &str) -> String {
        match (self, comment.strip_suffix(version)) {
            (Self::Rev, Some(prefix)) => format!("{prefix}{tag}"),
            _ => self.new_comment(tag),
        }
    }
}

/// The different states that can come from [`RefVersionMismatch::detect_version_comment`].
#[derive(Debug)]
enum VersionCommentState<'doc> {
    /// No version comment was detected.
    Missing,
    /// A version comment was detected.
    Version {
        version: &'doc str,
        comment: &'doc Comment<'doc>,
    },
    /// There was a comment (or comments), but none of them were version comments.
    NonVersionComments,
}

impl RefVersionMismatch {
    fn extract_version_from_comments<'doc>(
        comments: &'doc [Comment<'doc>],
    ) -> Option<(&'doc str, &'doc Comment<'doc>)> {
        for comment in comments {
            if let Some(version) = RawVersion::from_comment(comment) {
                return Some((version.as_raw(), comment));
            }
        }
        None
    }

    fn detect_version_comment<'doc>(comments: &'doc [Comment<'doc>]) -> VersionCommentState<'doc> {
        match Self::extract_version_from_comments(comments) {
            Some((version, comment)) => VersionCommentState::Version { version, comment },
            None if comments.is_empty() => VersionCommentState::Missing,
            None => VersionCommentState::NonVersionComments,
        }
    }

    /// Create a Fix for updating the version comment to match the pinned hash
    fn update_version_comment_fix<'a, 'doc, S>(
        parent: &'a S,
        key: RefKey,
        new_comment: String,
        correct_tag: &str,
    ) -> Fix<'doc>
    where
        S: Locatable<'doc> + AsDocument<'a, 'doc>,
    {
        Fix {
            title: format!("update version comment to match pinned hash: {correct_tag}"),
            key: parent.location().key,
            disposition: Default::default(),
            patches: vec![Patch {
                route: parent.route().with_key(key.as_str()),
                operation: Op::ReplaceComment {
                    new: new_comment.into(),
                },
            }],
        }
    }

    /// Create a Fix for adding a version comment where none exists
    fn add_version_comment_fix<'a, 'doc, S>(parent: &'a S, key: RefKey, tag: &str) -> Fix<'doc>
    where
        S: Locatable<'doc> + AsDocument<'a, 'doc>,
    {
        Fix {
            title: format!("add version comment: {tag}"),
            key: parent.location().key,
            disposition: Default::default(),
            patches: vec![Patch {
                route: parent.route().with_key(key.as_str()),
                operation: Op::EmplaceComment {
                    new: key.new_comment(tag).into(),
                },
            }],
        }
    }

    /// Check a pinned ref against its version comment.
    ///
    /// `key` is the YAML key holding the ref within `parent`, and `raw` is
    /// that key's raw value (used to underline the ref in findings).
    async fn process_ref<'a, 'doc, S>(
        &self,
        repo_ref: RepoRef<'doc>,
        key: RefKey,
        raw: &'doc str,
        parent: &'a S,
    ) -> Result<Option<Finding<'doc>>, AuditError>
    where
        S: Locatable<'doc> + AsDocument<'a, 'doc>,
    {
        // Only check refs that are commits (not symbolic refs like v1.0.0)
        let Some(commit_sha) = repo_ref.commit_ref() else {
            return Ok(None);
        };

        // We can only look up refs for GitHub repositories.
        let Some(slug) = repo_ref.slug() else {
            return Ok(None);
        };

        let parent_location = parent.location();
        let uses_location = parent_location
            .with_keys([key.as_str().into()])
            .concretize(parent.as_document())
            .map_err(Self::err)?;

        let comment_version_state = Self::detect_version_comment(&uses_location.concrete.comments);

        let (version, comment) = match comment_version_state {
            VersionCommentState::Version { version, comment } => (version, comment),
            VersionCommentState::Missing | VersionCommentState::NonVersionComments => {
                // SHA-pinned action without a recognized version comment.
                let Some(tag) = self
                    .client
                    .longest_tag_for_commit(&slug, repo_ref.subpath(), commit_sha)
                    .await
                    .map_err(Self::err)?
                else {
                    return Ok(None);
                };

                let (annotation, tip) = match comment_version_state {
                    VersionCommentState::Missing => (
                        "missing version comment",
                        format!("add version comment '{}'", key.new_comment(&tag.name)),
                    ),
                    VersionCommentState::NonVersionComments => (
                        "comment does not contain a version",
                        format!(
                            "rewrite comment to include '{}'",
                            key.new_comment(&tag.name)
                        ),
                    ),
                    VersionCommentState::Version { .. } => unreachable!(),
                };

                let mut builder = Self::finding()
                    .severity(Severity::Low)
                    .confidence(Confidence::High)
                    .persona(Persona::Pedantic)
                    .add_location(parent_location.hidden())
                    .add_location(
                        uses_location
                            .symbolic
                            .primary()
                            .subfeature(Subfeature::new(0, raw))
                            .annotated(annotation),
                    )
                    .tip(tip);

                if matches!(comment_version_state, VersionCommentState::Missing) {
                    builder = builder.fix(Self::add_version_comment_fix(parent, key, &tag.name));
                }

                return Ok(Some(builder.build(parent).map_err(Self::err)?));
            }
        };

        let git_ref = self
            .client
            .lookup_ref(&slug, version)
            .await
            .map_err(Self::err)?;

        // If the ref matches, there's nothing to do.
        if git_ref.as_ref().map(|r| r.commit()) == Some(commit_sha) {
            return Ok(None);
        }

        // Bug #2393: the user might try to use a block-style YAML string for the `uses:` clause,
        // and then try and put the version comment next to the block start (e.g. `uses: |- # 1.2.3`).
        //
        // Previously this would cause a hard crash because the subfeature previously assumed that the
        // comment comes *after* the `uses:` clause's contents, which isn't true in that case.
        //
        // Note that this is arguably not correct either: Dependabot and other tools expect the version
        // comment to be on the same line as the `org/repo` reference, not just anywhere on the
        // `uses:` clause. We could pretty easily reject this in the future instead by checking whether the
        // comment's start is before the end of the `uses:` clause.
        let subfeature = Subfeature::new(comment.location().offset_span.start, version);

        let comment_location = match git_ref {
            Some(commit_for_ref) => Location::new(
                uses_location.symbolic.clone().primary().annotated(format!(
                    "{kind} points to commit {short_commit}",
                    kind = commit_for_ref.kind(),
                    short_commit = &commit_for_ref.commit()[..12]
                )),
                Feature::from_subfeature(&subfeature, parent),
            ),
            None => Location::new(
                uses_location
                    .symbolic
                    .clone()
                    .primary()
                    .annotated("points to unknown ref"),
                Feature::from_subfeature(&subfeature, parent),
            ),
        };

        let mut builder = Self::finding()
            .severity(Severity::Medium)
            .confidence(Confidence::High)
            .add_location(parent.location().hidden())
            .add_raw_location(comment_location);

        if let Some(suggestion) = self
            .client
            .longest_tag_for_commit(&slug, repo_ref.subpath(), commit_sha)
            .await
            .map_err(Self::err)?
        {
            builder = builder.add_location(parent_location.hidden()).add_location(
                uses_location
                    .symbolic
                    .subfeature(Subfeature::new(0, raw))
                    .annotated(format!("is pointed to by tag {tag}", tag = suggestion.name)),
            );
            // Add auto-fix to update the version comment to match the pinned hash
            let new_comment = key.updated_comment(comment.as_raw(), version, &suggestion.name);
            builder = builder.fix(Self::update_version_comment_fix(
                parent,
                key,
                new_comment,
                &suggestion.name,
            ));
        }

        Ok(Some(builder.build(parent).map_err(Self::err)?))
    }

    async fn process_step<'doc, S: StepCommon<'doc>>(
        &self,
        step: &S,
    ) -> Result<Option<Finding<'doc>>, AuditError> {
        let Some(Uses::Repository(uses)) = step.uses() else {
            return Ok(None);
        };

        self.process_ref(uses.into(), RefKey::Uses, uses.raw(), step)
            .await
    }
}

#[async_trait::async_trait]
impl Audit for RefVersionMismatch {
    fn new(state: &AuditState) -> Result<Self, AuditLoadError> {
        if state.no_online_audits {
            return Err(AuditLoadError::Skip(anyhow!(
                "offline audits only requested"
            )));
        }

        state
            .gh_client
            .clone()
            .ok_or_else(|| AuditLoadError::Skip(anyhow!("can't run without a GitHub API token")))
            .map(|client| Self { client })
    }

    async fn audit_step<'doc>(
        &self,
        step: &Step<'doc>,
        group: &crate::registry::input::InputGroup,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        // If we have a lockfile and this step's workflow is present in it,
        // then there are no possible mismatches.
        if let Some(lock) = group.lock()
            && lock.is_locked(step.as_ref())
        {
            debug_once!(
                "{input} is covered by a lockfile, no ref-version-mismatch checks needed",
                input = step.as_ref()
            );

            return Ok(vec![]);
        }

        Ok(self.process_step(step).await?.into_iter().collect())
    }

    async fn audit_composite_step<'doc>(
        &self,
        step: &CompositeStep<'doc>,
        _group: &crate::registry::input::InputGroup,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        Ok(self.process_step(step).await?.into_iter().collect())
    }

    async fn audit_reusable_job<'doc>(
        &self,
        job: &ReusableWorkflowCallJob<'doc>,
        _group: &crate::registry::input::InputGroup,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let Uses::Repository(uses) = &job.uses else {
            return Ok(vec![]);
        };

        Ok(self
            .process_ref(uses.into(), RefKey::Uses, uses.raw(), job)
            .await?
            .into_iter()
            .collect())
    }

    async fn audit_pre_commit_config_repo<'doc>(
        &self,
        repo: &pre_commit::Repo<'doc>,
        _group: &crate::registry::input::InputGroup,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        // `local`, `meta`, etc. have no remote ref to check.
        let Some(remote) = repo.repo() else {
            return Ok(vec![]);
        };

        let repo_ref = RepoRef::from(remote);
        if repo_ref.commit_ref().is_some() && repo_ref.slug().is_none() {
            tracing::debug!(
                "ref-version-mismatch: skipping non-GitHub pre-commit repo {url}",
                url = remote.repo.as_str()
            );
            return Ok(vec![]);
        }

        Ok(self
            .process_ref(repo_ref, RefKey::Rev, &remote.rev, repo)
            .await?
            .into_iter()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use super::*;
    use crate::{models::action::Action, registry::input::InputKey};

    #[test]
    fn test_comment_version_state_with_unrelated_comment() {
        let action_content = r#"
name: Test Missing Version Comment
description: Test Missing Version Comment
runs:
  using: composite
  steps:
    - name: Checkout with unrelated comment
      uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # some comment
"#;

        let key = InputKey::local("fakegroup".into(), "action.yml", None, None);
        let action = Action::from_string(action_content.to_string(), key).unwrap();
        let step = action.steps().unwrap().next().unwrap();
        let uses_location = step
            .location()
            .with_keys(["uses".into()])
            .concretize(step.document())
            .unwrap();

        assert_matches!(
            RefVersionMismatch::detect_version_comment(&uses_location.concrete.comments),
            VersionCommentState::NonVersionComments,
        );
    }
}
