use std::{sync::LazyLock, vec};

use anyhow::Context as _;
use github_actions_models::common::{Uses, expr::LoE};
use subfeature::Subfeature;
use tree_sitter::StreamingIterator as _;

use super::{Audit, AuditLoadError, audit_meta};
use crate::audit::AuditError;
use crate::finding::location::{Locatable as _, SymbolicLocation};
use crate::{
    finding::{Confidence, Finding, Severity},
    models::{
        StepBodyCommon, StepCommon,
        coordinate::{ActionCoordinate, ControlExpr, ControlFieldType, Toggle},
        workflow::JobCommon as _,
    },
    state::AuditState,
    utils,
};

const USES_MANUAL_CREDENTIAL: &str =
    "uses a manually-configured credential instead of Trusted Publishing";

const KNOWN_RUBY_TP_INDICES: &[&str] = &["https://rubygems.org"];

const KNOWN_PYTHON_TP_INDICES: &[&str] = &[
    "https://upload.pypi.org/legacy/",
    "https://test.pypi.org/legacy/",
];

const KNOWN_NPMJS_TP_INDICES: &[&str] =
    &["https://registry.npmjs.org", "https://registry.npmjs.org/"];

const JS_TOKEN_AUTH_ENV_VARS: &[&str] = &["NODE_AUTH_TOKEN", "NPM_TOKEN", "YARN_NPM_AUTH_TOKEN"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublishCommandKind {
    Other,
    JsTrustedPublishing,
    Bun,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RegistryKind {
    Npmjs,
    NonNpmjs,
    Unknown,
}

#[derive(Clone, Debug)]
struct PublishCommandCandidate<'doc> {
    command: Subfeature<'doc>,
    kind: PublishCommandKind,
    registry: Option<RegistryKind>,
    inline_token_assignment: Option<Subfeature<'doc>>,
}

#[allow(clippy::unwrap_used)]
static KNOWN_TRUSTED_PUBLISHING_ACTIONS: LazyLock<Vec<(ActionCoordinate, &[&str])>> =
    LazyLock::new(|| {
        vec![
            (
                ActionCoordinate::Configurable {
                    uses_pattern: "pypa/gh-action-pypi-publish".parse().unwrap(),
                    control: ControlExpr::all([
                        ControlExpr::single(
                            Toggle::OptIn,
                            "password",
                            ControlFieldType::FreeString,
                            false,
                        ),
                        // TIP: On first glance you might think this should be
                        // `any` instead, but observe that each of these control
                        // expressions is marked with `enabled_by_default: true`.
                        // If we used `any` we'd end up accidentally satisfying
                        // when the user only sets one of the control fields.
                        ControlExpr::all([
                            ControlExpr::single(
                                Toggle::OptIn,
                                "repository-url",
                                ControlFieldType::Exact(KNOWN_PYTHON_TP_INDICES),
                                true,
                            ),
                            ControlExpr::single(
                                Toggle::OptIn,
                                "repository_url",
                                ControlFieldType::Exact(KNOWN_PYTHON_TP_INDICES),
                                true,
                            ),
                        ]),
                    ]),
                },
                &["with", "password"],
            ),
            // TODO: Not sufficiently sensitive; we need to detect whether
            // a TP-compatible registry is being published to.
            // (
            //     ActionCoordinate::Configurable {
            //         uses_pattern: "PyO3/maturin-action".parse().unwrap(),
            //         control: ControlExpr::single(
            //             Toggle::OptIn,
            //             "command",
            //             ControlFieldType::Exact(&["upload", "publish"]),
            //             true,
            //         ),
            //     },
            //     &["with", "command"],
            // ),
            (
                ActionCoordinate::Configurable {
                    uses_pattern: "rubygems/release-gem".parse().unwrap(),
                    control: ControlExpr::not(ControlExpr::single(
                        Toggle::OptIn,
                        "setup-trusted-publisher",
                        ControlFieldType::Boolean,
                        true,
                    )),
                },
                &["with", "setup-trusted-publisher"],
            ),
            (
                ActionCoordinate::Configurable {
                    uses_pattern: "rubygems/configure-rubygems-credentials".parse().unwrap(),
                    control: ControlExpr::all([
                        ControlExpr::single(
                            Toggle::OptIn,
                            "api-token",
                            ControlFieldType::FreeString,
                            false,
                        ),
                        ControlExpr::single(
                            Toggle::OptIn,
                            "gem-server",
                            ControlFieldType::Exact(KNOWN_RUBY_TP_INDICES),
                            true,
                        ),
                    ]),
                },
                &["with", "api-token"],
            ),
            // NPM publishing actions that should use trusted publishing
            // Detects when actions/setup-node is configured for npmjs with always-auth
            (
                ActionCoordinate::Configurable {
                    uses_pattern: "actions/setup-node".parse().unwrap(),
                    control: ControlExpr::all([
                        ControlExpr::single(
                            Toggle::OptIn,
                            "registry-url",
                            ControlFieldType::Exact(KNOWN_NPMJS_TP_INDICES),
                            true,
                        ),
                        // Detect when always-auth is enabled (indicating manual token usage)
                        ControlExpr::single(
                            Toggle::OptIn,
                            "always-auth",
                            ControlFieldType::Boolean,
                            false,
                        ),
                    ]),
                },
                &["with", "always-auth"],
            ),
        ]
    });

const BASH_COMMAND_QUERY: &str = "(command name: (_) @cmd argument: (_)+ @args) @span";
const PWSH_COMMAND_QUERY: &str =
    "(command command_name: (_) @cmd command_elements: (_ (generic_token) @args)+) @span";

pub(crate) struct UseTrustedPublishing {
    bash_command_query: utils::SpannedQuery,
    pwsh_command_query: utils::SpannedQuery,
}

audit_meta!(
    UseTrustedPublishing,
    "use-trusted-publishing",
    "prefer trusted publishing for authentication"
);

impl UseTrustedPublishing {
    fn query<'a>(
        &self,
        query: &'a utils::SpannedQuery,
        cursor: &'a mut tree_sitter::QueryCursor,
        tree: &'a tree_sitter::Tree,
        source: &'a str,
    ) -> tree_sitter::QueryMatches<'a, 'a, &'a [u8], &'a [u8]> {
        cursor.matches(query, tree.root_node(), source.as_bytes())
    }

    #[cfg(test)]
    fn is_publish_command<'a>(cmd: &'a str, args: impl Iterator<Item = &'a str>) -> bool {
        Self::publish_command_kind(cmd, args).is_some()
    }

    /// Classify the given command and arguments if they correspond to a publishing
    /// command, e.g., `cargo publish`, `twine upload`, etc.
    fn publish_command_kind<'a>(
        cmd: &'a str,
        args: impl Iterator<Item = &'a str>,
    ) -> Option<PublishCommandKind> {
        // NOTE(ww): The implementation below is frustratingly manual.
        // Ideally we'd use clap or similar to define an (imprecise) model of what we're
        // looking for, but as of 2025-11 none of the popular Rust command-line parsing
        // libraries do a great job of handling unknown commands and arguments (which we want,
        // because we don't want to have to define a perfectly accurate model for all
        // of the commands we're trying to match).
        let mut args = args;

        match cmd {
            "cargo" => {
                // Looking for `cargo ... publish` without `--dry-run` or `-n`.

                (args.any(|arg| arg == "publish")
                    && args.all(|arg| arg != "--dry-run" && arg != "-n"))
                .then_some(PublishCommandKind::Other)
            }
            "uv" => {
                match args.find(|arg| *arg == "publish" || *arg == "run") {
                    Some("publish") => {
                        // `uv ... publish` without `--dry-run`.
                        args.all(|arg| arg != "--dry-run")
                            .then_some(PublishCommandKind::Other)
                    }
                    Some("run") => {
                        // `uv ... run ... twine ... upload`.
                        (args.any(|arg| arg == "twine") && args.any(|arg| arg == "upload"))
                            .then_some(PublishCommandKind::Other)
                    }
                    _ => None,
                }
            }
            "uvx" => {
                // Looking for `uvx twine ... upload`.
                // Like with pipx, we loosely match the `twine` part
                // to allow for version specifiers. In uvx's case, these
                // are formatted like `twine@X.Y.Z`.

                (args.any(|arg| arg.starts_with("twine")) && args.any(|arg| arg == "upload"))
                    .then_some(PublishCommandKind::Other)
            }
            "hatch" | "pdm" => {
                // Looking for `hatch ... publish` or `pdm ... publish`.
                args.any(|arg| arg == "publish")
                    .then_some(PublishCommandKind::Other)
            }
            "poetry" => {
                // Looking for `poetry ... publish` without `--dry-run`.
                //
                // Poetry has no support for Trusted Publishing at all as
                // of 2025-12-1: https://github.com/python-poetry/poetry/issues/7940
                (args.any(|arg| arg == "publish") && args.all(|arg| arg != "--dry-run"))
                    .then_some(PublishCommandKind::Other)
            }
            "twine" => {
                // Looking for `twine ... upload`.
                args.any(|arg| arg == "upload")
                    .then_some(PublishCommandKind::Other)
            }
            "pipx" => {
                // TODO: also match `pipx ... run ... uv ... publish`, etc.

                // Looking for `pipx ... run ... twine ... upload`.
                //
                // A wrinkle here is that `pipx run` takes version specifiers
                // too, e.g. `pipx run twine==X.Y.Z upload ...`. So we only
                // loosely match the `twine` part.
                (args.any(|arg| arg == "run")
                    && args.any(|arg| arg.starts_with("twine"))
                    && args.any(|arg| arg == "upload"))
                .then_some(PublishCommandKind::Other)
            }
            _ if cmd.starts_with("python") => {
                // Looking for `python* ... -m ... twine ... upload`.
                (args.any(|arg| arg == "-m")
                    && args.any(|arg| arg == "twine")
                    && args.any(|arg| arg == "upload"))
                .then_some(PublishCommandKind::Other)
            }
            "gem" => {
                // Looking for `gem ... push`.
                args.any(|arg| arg == "push")
                    .then_some(PublishCommandKind::Other)
            }
            "bundle" => {
                // Looking for `bundle ... exec ... gem ... push`.
                (args.any(|arg| arg == "exec")
                    && args.any(|arg| arg == "gem")
                    && args.any(|arg| arg == "push"))
                .then_some(PublishCommandKind::Other)
            }
            "npm" => {
                // Looking for `npm ... publish` without `--dry-run`.

                // TODO: Figure out `npm run ... publish` patterns.
                (args.any(|arg| arg == "publish") && args.all(|arg| arg != "--dry-run"))
                    .then_some(PublishCommandKind::JsTrustedPublishing)
            }
            "yarn" => {
                // Looking for `yarn ... publish` for Yarn v1,
                // and `yarn ... npm ... publish` without `--dry-run` or `-n` for Yarn v2+.
                match args.find(|arg| *arg == "publish" || *arg == "npm") {
                    Some("publish") => Some(PublishCommandKind::JsTrustedPublishing),
                    Some("npm") => {
                        // `yarn ... npm ... publish` without `--dry-run` or `-n`.
                        (args.any(|arg| arg == "publish")
                            && args.all(|arg| arg != "--dry-run" && arg != "-n"))
                        .then_some(PublishCommandKind::JsTrustedPublishing)
                    }
                    _ => None,
                }
            }
            "pnpm" => {
                // TODO: Figure out `pnpm run ... publish` patterns.

                // Looking for `pnpm ... publish` without `--dry-run`.
                (args.any(|arg| arg == "publish") && args.all(|arg| arg != "--dry-run"))
                    .then_some(PublishCommandKind::JsTrustedPublishing)
            }
            "bunx" => {
                // Looking for `bunx npm ... publish` without `--dry-run`.
                // We loosely match `npm` to allow for version specifiers
                // (e.g. `npm@11`).
                match args.find(|arg| *arg == "npm" || arg.starts_with("npm@")) {
                    Some(_) => (args.any(|arg| arg == "publish")
                        && args.all(|arg| arg != "--dry-run"))
                    .then_some(PublishCommandKind::JsTrustedPublishing),
                    None => None,
                }
            }
            "bun" => {
                // Looking for `bun ... publish` without `--dry-run`.
                (args.any(|arg| arg == "publish") && args.all(|arg| arg != "--dry-run"))
                    .then_some(PublishCommandKind::Bun)
            }
            "nuget" | "nuget.exe" => {
                // Looking for `nuget ... push`.
                args.any(|arg| arg == "push")
                    .then_some(PublishCommandKind::Other)
            }
            "dotnet" => {
                // Looking for `dotnet ... nuget ... push`.
                (args.any(|arg| arg == "nuget") && args.any(|arg| arg == "push"))
                    .then_some(PublishCommandKind::Other)
            }
            _ => None,
        }
    }

    fn registry_kind(registry: &str) -> RegistryKind {
        let registry = registry
            .trim()
            .trim_matches(['"', '\''])
            .trim_end_matches('/');

        if registry.contains("${{") || registry.contains('$') {
            RegistryKind::Unknown
        } else if registry == "https://registry.npmjs.org" {
            RegistryKind::Npmjs
        } else if registry.is_empty() {
            RegistryKind::Unknown
        } else {
            RegistryKind::NonNpmjs
        }
    }

    fn publish_registry_kind(cmd: &str, args: &[&str]) -> Option<RegistryKind> {
        match cmd {
            "npm" | "pnpm" | "bunx" | "yarn" => {}
            _ => return None,
        }

        let mut args = args.iter();
        while let Some(arg) = args.next() {
            let arg = arg.trim_matches(['"', '\'']);

            if let Some(registry) = arg.strip_prefix("--registry=") {
                return Some(Self::registry_kind(registry));
            }

            if arg == "--registry"
                && let Some(registry) = args.next()
            {
                return Some(Self::registry_kind(registry));
            }
        }

        None
    }

    fn npm_config_registry_kind(cmd: &str, args: &[&str]) -> Option<RegistryKind> {
        if !matches!(cmd, "npm" | "pnpm") || args.len() < 3 {
            return None;
        }

        if args[0] != "config" || args[1] != "set" {
            return None;
        }

        let registry_arg = args[2].trim_matches(['"', '\'']);

        if registry_arg == "registry" {
            return args.get(3).map(|registry| Self::registry_kind(registry));
        }

        registry_arg
            .strip_prefix("registry=")
            .map(Self::registry_kind)
    }

    fn prior_setup_node_registry_kind(step: &crate::models::workflow::Step<'_>) -> RegistryKind {
        let mut registry = RegistryKind::Unknown;

        for prior in step
            .parent
            .steps()
            .take_while(|prior| prior.index < step.index)
        {
            let StepBodyCommon::Uses {
                uses: Uses::Repository(uses),
                with,
            } = prior.body()
            else {
                continue;
            };

            if !uses.owner().eq_ignore_ascii_case("actions")
                || !uses.repo().eq_ignore_ascii_case("setup-node")
            {
                continue;
            }

            let LoE::Literal(with) = with else {
                registry = RegistryKind::Unknown;
                continue;
            };

            registry = with
                .get("registry-url")
                .map(|registry| Self::registry_kind(&registry.to_string()))
                .unwrap_or(RegistryKind::Unknown);
        }

        registry
    }

    fn find_inline_js_token_assignment<'doc>(
        run: &'doc str,
        command: tree_sitter::Node<'_>,
    ) -> Option<Subfeature<'doc>> {
        let mut cursor = command.walk();

        command.named_children(&mut cursor).find_map(|child| {
            if child.kind() != "variable_assignment" {
                return None;
            }

            let name = child
                .child_by_field_name("name")?
                .utf8_text(run.as_bytes())
                .expect("impossible: capture should be UTF-8 by construction");

            JS_TOKEN_AUTH_ENV_VARS.contains(&name).then(|| {
                let assignment = child
                    .utf8_text(run.as_bytes())
                    .expect("impossible: capture should be UTF-8 by construction");
                Subfeature::new(child.start_byte(), assignment)
            })
        })
    }

    /// Check step, job, and workflow env blocks for JS token auth env vars
    /// inherited by a JS publish command. Returns a `SymbolicLocation`
    /// pointing at the matching variable.
    fn find_js_token_env_var_in_step<'doc>(
        step: &crate::models::workflow::Step<'doc>,
    ) -> Option<SymbolicLocation<'doc>> {
        // Check step-level env first (most specific)
        if let LoE::Literal(env) = &step.env
            && let Some(var) = JS_TOKEN_AUTH_ENV_VARS
                .iter()
                .find(|var| env.contains_key(**var))
        {
            return Some(
                step.location()
                    .with_keys(["env".into(), (*var).into()])
                    .annotated(USES_MANUAL_CREDENTIAL),
            );
        }
        // Check job-level env
        if let LoE::Literal(env) = &step.parent.env
            && let Some(var) = JS_TOKEN_AUTH_ENV_VARS
                .iter()
                .find(|var| env.contains_key(**var))
        {
            return Some(
                step.job()
                    .location()
                    .with_keys(["env".into(), (*var).into()])
                    .annotated(USES_MANUAL_CREDENTIAL),
            );
        }
        // Check workflow-level env
        if let LoE::Literal(env) = &step.workflow().env
            && let Some(var) = JS_TOKEN_AUTH_ENV_VARS
                .iter()
                .find(|var| env.contains_key(**var))
        {
            return Some(
                step.workflow()
                    .location()
                    .with_keys(["env".into(), (*var).into()])
                    .annotated(USES_MANUAL_CREDENTIAL),
            );
        }
        None
    }

    fn publish_command_finding<'doc>(
        step: &impl StepCommon<'doc>,
        command: Subfeature<'doc>,
        credential_location: Option<SymbolicLocation<'doc>>,
    ) -> Result<Finding<'doc>, AuditError> {
        let mut finding = Self::finding()
            .severity(Severity::Informational)
            .confidence(Confidence::High)
            .add_location(step.location().hidden())
            .add_location(
                step.location()
                    .with_keys(["run".into()])
                    .key_only()
                    .annotated("this step"),
            )
            .add_location(
                step.location()
                    .primary()
                    .with_keys(["run".into()])
                    .subfeature(command)
                    .annotated("this command"),
            );

        if let Some(credential_location) = credential_location {
            finding = finding.add_location(credential_location);
        }

        finding.build(step)
    }

    fn candidate_uses_non_npmjs_registry(
        candidate: &PublishCommandCandidate<'_>,
        setup_node_registry: RegistryKind,
    ) -> bool {
        candidate.registry == Some(RegistryKind::NonNpmjs)
            || (candidate.registry.is_none() && setup_node_registry == RegistryKind::NonNpmjs)
    }

    fn js_manual_auth_location<'doc>(
        step: &crate::models::workflow::Step<'doc>,
        inline_token_assignment: Option<Subfeature<'doc>>,
    ) -> Option<SymbolicLocation<'doc>> {
        inline_token_assignment
            .map(|inline| {
                step.location()
                    .with_keys(["run".into()])
                    .subfeature(inline)
                    .annotated(USES_MANUAL_CREDENTIAL)
            })
            .or_else(|| Self::find_js_token_env_var_in_step(step))
    }

    fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        for (coordinate, keys) in KNOWN_TRUSTED_PUBLISHING_ACTIONS.iter() {
            // TODO: Capture the Some(Usage) here and specialize the
            // finding with it.
            if coordinate.usage(step).is_some() {
                findings.push(
                    Self::finding()
                        .severity(Severity::Informational)
                        .confidence(Confidence::High)
                        .add_location(step.location().hidden())
                        .add_location(
                            step.location()
                                .primary()
                                .with_keys(["uses".into()])
                                .annotated("this step"),
                        )
                        .add_location(
                            step.location()
                                .primary()
                                .with_keys(keys.iter().map(|k| (*k).into()))
                                .annotated(USES_MANUAL_CREDENTIAL),
                        )
                        .build(step)?,
                );
            }
        }

        Ok(findings)
    }

    fn trusted_publishing_command_candidates<'doc>(
        &self,
        run: &'doc str,
        shell: &str,
    ) -> Result<Vec<PublishCommandCandidate<'doc>>, AuditError> {
        let normalized = utils::normalize_shell(shell);

        let mut cursor = tree_sitter::QueryCursor::new();
        let (query, tree) = match normalized {
            "bash" | "sh" | "zsh" => {
                let mut parser = utils::bash_parser();
                let tree = parser
                    .parse(run, None)
                    .context("failed to parse `run:` body as bash")
                    .map_err(Self::err)?;

                (&self.bash_command_query, tree)
            }
            "pwsh" | "powershell" => {
                let mut parser = utils::pwsh_parser();
                let tree = parser
                    .parse(run, None)
                    .context("failed to parse `run:` body as pwsh")
                    .map_err(Self::err)?;

                (&self.pwsh_command_query, tree)
            }
            _ => {
                tracing::debug!("unable to analyze 'run:' block: unknown shell '{normalized}'");
                return Ok(vec![]);
            }
        };

        let matches = self.query(query, &mut cursor, &tree, run);
        let cmd = query
            .capture_index_for_name("cmd")
            .expect("internal error: missing capture index for 'cmd'");
        let args = query
            .capture_index_for_name("args")
            .expect("internal error: missing capture index for 'args'");

        let mut subfeatures = vec![];
        let mut configured_registry = None;
        matches.for_each(|mat| {
            let cmd = {
                let cap = mat
                    .captures
                    .iter()
                    .find(|cap| cap.index == cmd)
                    .expect("internal error: expected capture for cmd");
                cap.node
                    .utf8_text(run.as_bytes())
                    .expect("impossible: capture should be UTF-8 by construction")
            };

            let args: Vec<_> = mat
                .captures
                .iter()
                .filter(|cap| cap.index == args)
                .map(|cap| {
                    cap.node
                        .utf8_text(run.as_bytes())
                        .expect("impossible: capture should be UTF-8 by construction")
                })
                .collect();

            if let Some(config_registry) = Self::npm_config_registry_kind(cmd, &args) {
                configured_registry = Some(config_registry);
            }

            if let Some(kind) = Self::publish_command_kind(cmd, args.iter().copied()) {
                let span = mat
                    .captures
                    .iter()
                    .find(|cap| cap.index == query.span_idx)
                    .expect("internal error: expected capture for span");

                let span_contents = span
                    .node
                    .utf8_text(run.as_bytes())
                    .expect("impossible: capture should be UTF-8 by construction");
                let inline_token_assignment = match kind {
                    PublishCommandKind::JsTrustedPublishing
                        if matches!(normalized, "bash" | "sh" | "zsh") =>
                    {
                        Self::find_inline_js_token_assignment(run, span.node)
                    }
                    _ => None,
                };
                let registry = Self::publish_registry_kind(cmd, &args).or(configured_registry);

                subfeatures.push(PublishCommandCandidate {
                    command: Subfeature::new(span.node.start_byte(), span_contents),
                    kind,
                    registry,
                    inline_token_assignment,
                });
            }
        });

        Ok(subfeatures)
    }
}

#[async_trait::async_trait]
impl Audit for UseTrustedPublishing {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError> {
        Ok(Self {
            bash_command_query: utils::SpannedQuery::new(BASH_COMMAND_QUERY, &utils::BASH),
            pwsh_command_query: utils::SpannedQuery::new(PWSH_COMMAND_QUERY, &utils::PWSH),
        })
    }

    async fn audit_step<'doc>(
        &self,
        step: &crate::models::workflow::Step<'doc>,
        _config: &crate::config::Config,
    ) -> Result<Vec<super::Finding<'doc>>, AuditError> {
        let mut findings = self.process_step(step)?;

        // In addition to the shared action matching above, we can
        // also check for some `run:` patterns that indicate publishing
        // without Trusted Publishing.

        // We can only check these reliably on workflows and not actions,
        // since we need to be able to see the `id-token` permission's
        // state to filter out any false positives.
        //
        // NOTE(ww): With #1161 we loosened this check and turned the
        // "has ID token" check into a confidence modifier rather than
        // a strict filter. This ended up being overly imprecise, since a lot
        // of publishing commands use trusted publishing implicitly if
        // the environment supports it. We reverted this with #1191.
        if let StepBodyCommon::Run { run, .. } = step.body() {
            let shell = step.shell().map(|s| s.0).unwrap_or_else(|| {
                tracing::debug!(
                    "use-trusted-publishing: couldn't determine shell type for {workflow}:{job} step {stepno}",
                    workflow = step.workflow().key.filename(),
                    job = step.parent.id(),
                    stepno = step.index
                );

                "bash"
            });

            let candidates = self.trusted_publishing_command_candidates(run, shell)?;

            if !step.parent.has_id_token() {
                // No id-token: flag ALL publish commands.
                for candidate in candidates {
                    findings.push(Self::publish_command_finding(
                        step,
                        candidate.command,
                        None,
                    )?);
                }
            } else {
                // id-token: write is present. For most non-JS commands, this is
                // sufficient evidence of trusted publishing, so we skip them.
                //
                // For JS package managers, `id-token: write` may be present
                // solely for `--provenance` attestation while the publish itself
                // still authenticates via a token env var (e.g. NODE_AUTH_TOKEN).
                // We flag these cases.
                //
                // `bun publish` does not support trusted publishing yet, so we
                // continue to flag it even when `id-token: write` is present.
                let setup_node_registry = Self::prior_setup_node_registry_kind(step);
                for candidate in candidates {
                    match candidate.kind {
                        PublishCommandKind::Other => continue,
                        PublishCommandKind::JsTrustedPublishing => {
                            if Self::candidate_uses_non_npmjs_registry(
                                &candidate,
                                setup_node_registry,
                            ) {
                                continue;
                            }

                            if let Some(credential_location) = Self::js_manual_auth_location(
                                step,
                                candidate.inline_token_assignment,
                            ) {
                                findings.push(Self::publish_command_finding(
                                    step,
                                    candidate.command,
                                    Some(credential_location),
                                )?);
                            }
                        }
                        PublishCommandKind::Bun => {
                            findings.push(Self::publish_command_finding(
                                step,
                                candidate.command,
                                None,
                            )?);
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    async fn audit_composite_step<'doc>(
        &self,
        step: &crate::models::action::CompositeStep<'doc>,
        _config: &crate::config::Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.process_step(step)
    }
}

#[cfg(test)]
mod tests {
    use subfeature::Fragment;

    use crate::audit::Audit;
    use crate::state::AuditState;

    #[test]
    fn test_is_publish_command() {
        for (args, is_publish_command) in &[
            (&["cargo", "publish"][..], true),
            (&["cargo", "publish", "-p", "foo"][..], true),
            (&["cargo", "publish", "--dry-run"][..], false),
            (&["cargo", "publish", "-n"][..], false),
            (&["cargo", "build"][..], false),
            (&["uv", "publish"][..], true),
            (&["uv", "publish", "dist/*"][..], true),
            (&["uv", "publish", "--dry-run"][..], false),
            (&["uv", "run", "--dev", "twine", "upload"][..], true),
            (&["uv", "run", "twine", "upload"][..], true),
            (&["uv"][..], false),
            (&["uv", "sync"][..], false),
            (&["uvx", "twine", "upload"][..], true),
            (&["uvx", "twine@3.4.1", "upload"][..], true),
            (&["uvx", "twine@6.1.0", "upload"][..], true),
            (&["uvx", "twine"][..], false),
            (&["poetry", "publish"][..], true),
            (&["poetry", "publish", "--dry-run"][..], false),
            (&["hatch", "publish"][..], true),
            (&["pdm", "publish"][..], true),
            (&["twine", "upload", "dist/*"][..], true),
            (&["pipx", "run", "twine", "upload", "dist/*"][..], true),
            (
                &["pipx", "run", "twine==3.4.1", "upload", "dist/*"][..],
                true,
            ),
            (
                &["pipx", "run", "twine==6.1.0", "upload", "dist/*"][..],
                true,
            ),
            (&["python", "-m", "twine", "upload", "dist/*"][..], true),
            (&["python3.9", "-m", "twine", "upload", "dist/*"][..], true),
            (&["twine", "check", "dist/*"], false),
            (&["gem", "push", "mygem-0.1.0.gem"][..], true),
            (
                &["bundle", "exec", "gem", "push", "mygem-0.1.0.gem"][..],
                true,
            ),
            (&["npm", "publish"][..], true),
            (&["npm", "run", "publish"][..], true),
            (&["npm", "publish", "--dry-run"][..], false),
            (&["yarn", "npm"][..], false),
            (&["yarn", "npm", "publish"][..], true),
            (&["yarn", "publish"][..], true),
            (&["yarn", "npm", "publish", "--dry-run"][..], false),
            (&["pnpm", "publish"][..], true),
            (&["pnpm", "publish", "--dry-run"][..], false),
            (&["bunx", "npm", "publish"][..], true),
            (&["bunx", "npm@11", "publish"][..], true),
            (&["bunx", "npm", "publish", "--dry-run"][..], false),
            (&["bunx", "npm", "view", "lodash"][..], false),
            (&["bun", "publish"][..], true),
            (&["bun", "publish", "--access", "public"][..], true),
            (&["bun", "publish", "--dry-run"][..], false),
            (&["bun", "install"][..], false),
            (&["nuget", "push", "MyPackage.nupkg"][..], true),
            (&["nuget.exe", "push", "MyPackage.nupkg"][..], true),
            (&["dotnet", "nuget", "push", "MyPackage.nupkg"][..], true),
            (&["dotnet", "build"][..], false),
        ] {
            let cmd = args[0];
            let args_iter = args[1..].iter().copied();
            assert_eq!(
                super::UseTrustedPublishing::is_publish_command(cmd, args_iter),
                *is_publish_command,
                "cmd: {cmd:?}, args: {args:?}"
            );
        }
    }

    #[test]
    fn test_inline_token_assignment_detection() {
        let audit_state = AuditState::default();
        let sut = super::UseTrustedPublishing::new(&audit_state).expect("failed to create audit");

        for (case, expected_count, expected_inline) in &[
            (
                "NODE_AUTH_TOKEN=foo npm publish --provenance",
                1,
                Some("NODE_AUTH_TOKEN=foo"),
            ),
            (
                "NODE_AUTH_TOKEN=foo yarn npm publish",
                1,
                Some("NODE_AUTH_TOKEN=foo"),
            ),
            (
                "YARN_NPM_AUTH_TOKEN=foo yarn publish",
                1,
                Some("YARN_NPM_AUTH_TOKEN=foo"),
            ),
            (
                "YARN_NPM_AUTH_TOKEN=foo npm publish",
                1,
                Some("YARN_NPM_AUTH_TOKEN=foo"),
            ),
            ("NPM_TOKEN=foo pnpm publish", 1, Some("NPM_TOKEN=foo")),
            ("NPM_TOKEN=foo yarn publish", 1, Some("NPM_TOKEN=foo")),
            ("FOO=bar npm publish --provenance", 1, None),
            ("NODE_AUTH_TOKEN=foo npm publish --dry-run", 0, None),
        ] {
            let candidates = sut
                .trusted_publishing_command_candidates(case, "bash")
                .expect("failed to extract publish candidates");

            assert_eq!(
                candidates.len(),
                *expected_count,
                "unexpected candidate count for {case:?}"
            );

            let inline = candidates
                .first()
                .and_then(|candidate| candidate.inline_token_assignment.as_ref())
                .map(|subfeature| match &subfeature.fragment {
                    Fragment::Raw(fragment) => *fragment,
                    Fragment::Regex(_) => panic!("unexpected regex fragment for {case:?}"),
                });

            assert_eq!(inline, *expected_inline, "failed: {case:?}");
        }
    }
}
