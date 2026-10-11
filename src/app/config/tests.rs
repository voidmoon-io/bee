//! Resolver tests. These drive [`resolve_from_layers`] with layers built in a temp directory
//! rather than [`resolve`], so nothing here depends on the developer's own `~/.config/bee/`.

use super::file::{load, Origin};
use super::*;

struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        Fixture {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Write a file and return its path.
    fn write(&self, name: &str, body: &str) -> PathBuf {
        let path = self.path(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, body).unwrap();
        path
    }

    /// A mock provider TOML — no network, no key.
    fn provider(&self, name: &str) -> PathBuf {
        self.write(
            name,
            "[provider]\nprovider = \"mock\"\n\n[[provider.script]]\ntext = \"hi\"\n",
        )
    }

    /// A policy file. `name` is the file name; the policy's own `name` field is that minus its
    /// extension, so a test can refer to the file by name from a config fixture.
    fn policy(&self, name: &str, body: &str) -> PathBuf {
        let label = name.trim_end_matches(".toml");
        self.write(name, &format!("[policy]\nname = \"{label}\"\n{body}"))
    }

    fn layer(&self, name: &str, origin: Origin, body: &str) -> Layer {
        let path = self.write(name, body);
        load(&path, origin).unwrap().unwrap()
    }
}

/// Flags naming a provider, so completeness is satisfied and a test can be about something else.
fn flags_with_provider(path: &Path) -> Flags {
    Flags {
        provider: Some(path.to_path_buf()),
        ..Flags::default()
    }
}

// --- completeness -----------------------------------------------------------------------------

#[test]
fn no_provider_anywhere_reports_where_it_could_come_from() {
    let err = resolve_from_layers(&[], &Flags::default()).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("incomplete configuration"), "{text}");
    assert!(text.contains("a provider"), "{text}");
    assert!(text.contains("--provider"), "{text}");
    assert!(text.contains("~/.config/bee/config.toml"), "{text}");
    // Project configuration may not supply a provider, so it must not be offered as a place to.
    assert!(!text.contains(".bee/config.toml"), "{text}");
}

#[test]
fn a_provider_from_user_configuration_completes_it() {
    let f = Fixture::new();
    f.provider("p.toml");
    let layer = f.layer(
        "config.toml",
        Origin::User,
        "[provider]\npath = \"p.toml\"\n",
    );
    let cfg = resolve_from_layers(&[layer], &Flags::default()).unwrap();
    assert_eq!(cfg.provider_path, f.path("p.toml"));
}

// --- precedence -------------------------------------------------------------------------------

#[test]
fn a_flag_beats_every_file() {
    let f = Fixture::new();
    let flag_provider = f.provider("flag.toml");
    f.provider("user.toml");
    f.provider("project.toml");
    f.provider("explicit.toml");

    let layers = vec![
        f.layer(
            "user-config.toml",
            Origin::User,
            "[provider]\npath = \"user.toml\"\n",
        ),
        f.layer(
            "project-config.toml",
            Origin::Project,
            "[session]\ntools = [\"bash\"]\n",
        ),
        f.layer(
            "explicit-config.toml",
            Origin::Explicit,
            "[provider]\npath = \"explicit.toml\"\n",
        ),
    ];
    let cfg = resolve_from_layers(&layers, &flags_with_provider(&flag_provider)).unwrap();
    assert_eq!(cfg.provider_path, flag_provider);
}

#[test]
fn explicit_beats_project_beats_user() {
    let f = Fixture::new();
    f.provider("p.toml");

    let user = f.layer(
        "user.toml",
        Origin::User,
        "[provider]\npath = \"p.toml\"\n[session]\nbudget = 1\n",
    );
    let project = f.layer("project.toml", Origin::Project, "[session]\nbudget = 2\n");
    let explicit = f.layer("explicit.toml", Origin::Explicit, "[session]\nbudget = 3\n");

    let only_user = resolve_from_layers(std::slice::from_ref(&user), &Flags::default()).unwrap();
    assert_eq!(only_user.budget, 1);

    let with_project =
        resolve_from_layers(&[user.clone(), project.clone()], &Flags::default()).unwrap();
    assert_eq!(with_project.budget, 2);

    let all = resolve_from_layers(&[user, project, explicit], &Flags::default()).unwrap();
    assert_eq!(all.budget, 3);

    // ...and the flag outranks all three.
    let f2 = Fixture::new();
    let provider = f2.provider("p.toml");
    let mut flags = flags_with_provider(&provider);
    flags.budget = Some(4);
    let cfg = resolve_from_layers(&[], &flags).unwrap();
    assert_eq!(cfg.budget, 4);
}

#[test]
fn precedence_is_per_field_not_per_file() {
    // The regression this guards: a project file that sets only the tool list must not blank out
    // the theme the user file set.
    let f = Fixture::new();
    f.provider("p.toml");
    let user = f.layer(
        "user.toml",
        Origin::User,
        "[provider]\npath = \"p.toml\"\n[theme]\nname = \"dracula\"\n[session]\nbudget = 9\n",
    );
    let project = f.layer(
        "project.toml",
        Origin::Project,
        "[session]\ntools = [\"bash\"]\n",
    );

    let cfg = resolve_from_layers(&[user, project], &Flags::default()).unwrap();
    assert_eq!(cfg.tools, vec!["bash".to_string()]);
    assert_eq!(cfg.budget, 9, "the user file's budget survived");
    assert_eq!(cfg.theme.name, "dracula", "the user file's theme survived");
}

#[test]
fn defaults_apply_when_nothing_configures_a_field() {
    let f = Fixture::new();
    let provider = f.provider("p.toml");
    let cfg = resolve_from_layers(&[], &flags_with_provider(&provider)).unwrap();
    assert_eq!(cfg.budget, DEFAULT_BUDGET);
    assert_eq!(cfg.turn_limit, DEFAULT_TURN_LIMIT);
    assert_eq!(cfg.timeout_secs, DEFAULT_TIMEOUT_SECS);
    assert_eq!(cfg.tools, DEFAULT_TOOLS);
    assert!(cfg.policy.is_none());
    assert!(cfg.system.is_none());
}

#[test]
fn paths_in_a_file_resolve_against_that_file() {
    let f = Fixture::new();
    f.provider("nested/p.toml");
    let layer = f.layer(
        "nested/config.toml",
        Origin::User,
        "[provider]\npath = \"p.toml\"\n",
    );
    let cfg = resolve_from_layers(&[layer], &Flags::default()).unwrap();
    assert_eq!(cfg.provider_path, f.path("nested/p.toml"));
}

// --- attenuation ------------------------------------------------------------------------------

#[test]
fn a_within_ceiling_request_is_derived() {
    let f = Fixture::new();
    let provider = f.provider("p.toml");
    let ceiling = f.policy(
        "ceiling.toml",
        "[policy.filesystem]\n\"/tmp\" = \"write\"\n",
    );
    let requested = f.policy(
        "requested.toml",
        "[policy.filesystem]\n\"/tmp\" = \"read\"\n",
    );

    let mut flags = flags_with_provider(&provider);
    flags.ceiling_policy = Some(ceiling);
    flags.policy = Some(requested);

    let cfg = resolve_from_layers(&[], &flags).unwrap();
    assert!(cfg.policy.is_some());
    assert!(cfg.ceiling.is_some());
}

#[test]
fn an_over_grant_is_refused_with_the_validators_own_words() {
    let f = Fixture::new();
    let provider = f.provider("p.toml");
    let ceiling = f.policy("ceiling.toml", "[policy.filesystem]\n\"/tmp\" = \"read\"\n");
    let requested = f.policy(
        "requested.toml",
        "[policy.filesystem]\n\"/tmp\" = \"write\"\n",
    );

    let mut flags = flags_with_provider(&provider);
    flags.ceiling_policy = Some(ceiling);
    flags.policy = Some(requested);

    let err = resolve_from_layers(&[], &flags).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("exceeds the ceiling"), "{text}");
    assert!(text.contains("/tmp"), "{text}");
}

#[test]
fn a_project_policy_request_is_bounded_by_the_user_ceiling() {
    // The end-to-end shape of the trust model: the ceiling can only come from a trusted layer, and
    // the untrusted layer's request is checked against it.
    let f = Fixture::new();
    f.provider("p.toml");
    f.policy("ceiling.toml", "[policy.filesystem]\n\"/tmp\" = \"read\"\n");
    f.policy("wanted.toml", "[policy.filesystem]\n\"/tmp\" = \"write\"\n");

    let user = f.layer(
        "user.toml",
        Origin::User,
        "[provider]\npath = \"p.toml\"\n[policy]\nceiling = \"ceiling.toml\"\n",
    );
    let project = f.layer(
        "project.toml",
        Origin::Project,
        "[policy]\npath = \"wanted.toml\"\n",
    );

    let err = resolve_from_layers(&[user, project], &Flags::default()).unwrap_err();
    assert!(err.to_string().contains("exceeds the ceiling"), "{err}");
}

#[test]
fn a_request_with_no_ceiling_stands_as_written() {
    let f = Fixture::new();
    let provider = f.provider("p.toml");
    let requested = f.policy(
        "requested.toml",
        "[policy.filesystem]\n\"/tmp\" = \"write\"\n",
    );
    let mut flags = flags_with_provider(&provider);
    flags.policy = Some(requested);

    let cfg = resolve_from_layers(&[], &flags).unwrap();
    assert!(cfg.policy.is_some());
    assert!(cfg.ceiling.is_none());
}

#[test]
fn a_ceiling_with_no_request_yields_no_policy() {
    let f = Fixture::new();
    let provider = f.provider("p.toml");
    let ceiling = f.policy("ceiling.toml", "[policy.filesystem]\n\"/tmp\" = \"read\"\n");
    let mut flags = flags_with_provider(&provider);
    flags.ceiling_policy = Some(ceiling);

    let cfg = resolve_from_layers(&[], &flags).unwrap();
    assert!(cfg.policy.is_none());
    assert!(cfg.ceiling.is_some());
}

// --- the two failure asymmetries ---------------------------------------------------------------

#[test]
fn an_unknown_theme_warns_but_an_unknown_visual_level_fails() {
    let f = Fixture::new();
    let provider = f.provider("p.toml");

    let mut theme_flags = flags_with_provider(&provider);
    theme_flags.theme = Some("no-such-theme".to_string());
    let cfg = resolve_from_layers(&[], &theme_flags).unwrap();
    assert!(cfg.theme_warning.is_some(), "an unknown theme must warn");

    let mut visual_flags = flags_with_provider(&provider);
    visual_flags.visual_level = Some("enormous".to_string());
    let err = resolve_from_layers(&[], &visual_flags).unwrap_err();
    assert!(err.to_string().contains("enormous"), "{err}");
}

#[test]
fn a_configured_visual_level_is_read_and_motion_stays_sticky() {
    let f = Fixture::new();
    f.provider("p.toml");
    let layer = f.layer(
        "user.toml",
        Origin::User,
        "[provider]\npath = \"p.toml\"\n[visual]\nlevel = \"takeover\"\nanimations = false\n",
    );
    let cfg = resolve_from_layers(&[layer], &Flags::default()).unwrap();
    assert_eq!(cfg.visual.level, bee::config::VisualLevel::Takeover);
    assert!(!cfg.visual.animations);
}

// --- bad inputs -------------------------------------------------------------------------------

#[test]
fn an_unreadable_provider_names_the_file() {
    let f = Fixture::new();
    let missing = f.path("nope.toml");
    let err = resolve_from_layers(&[], &flags_with_provider(&missing)).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("provider"), "{text}");
    assert!(text.contains("nope.toml"), "{text}");
}

#[test]
fn an_unreadable_policy_names_the_file() {
    let f = Fixture::new();
    let provider = f.provider("p.toml");
    let mut flags = flags_with_provider(&provider);
    flags.policy = Some(f.path("nope.toml"));
    let err = resolve_from_layers(&[], &flags).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("policy"), "{text}");
    assert!(text.contains("nope.toml"), "{text}");
}

// --- [context] (025) ----------------------------------------------------------------------------

#[test]
fn context_merges_key_by_key_across_layers() {
    let f = Fixture::new();
    f.provider("p.toml");
    let user = f.layer(
        "user.toml",
        Origin::User,
        "[provider]\npath = \"p.toml\"\n[context]\nwindow_tokens = 100000\nsoft = 0.5\n",
    );
    let project = f.layer(
        "project.toml",
        Origin::Project,
        "[context]\nwindow_tokens = 32000\n",
    );
    let cfg = resolve_from_layers(&[user, project], &Flags::default()).unwrap();
    assert_eq!(cfg.context.window_tokens, Some(32_000), "the project wins");
    assert_eq!(cfg.context.soft, Some(0.5), "the user's other keys survive");
}

#[test]
fn context_defaults_to_unset() {
    let f = Fixture::new();
    let provider = f.provider("p.toml");
    let cfg = resolve_from_layers(&[], &flags_with_provider(&provider)).unwrap();
    assert_eq!(cfg.context, bee::context::ContextConfig::default());
}

#[test]
fn an_unknown_context_key_is_refused() {
    let f = Fixture::new();
    let path = f.write("user.toml", "[context]\nwindow = 1000\n");
    assert!(load(&path, Origin::User).is_err());
}
