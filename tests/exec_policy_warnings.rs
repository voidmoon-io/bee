use bee_core::Policy;
use bee_userspace::{resolve::exec_path_warnings, SystemResolver};
use std::os::unix::fs::symlink;

#[test]
fn validation_warns_without_rewriting_symlink_grants() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    std::fs::write(&target, "fixture").unwrap();
    let target = target.canonicalize().unwrap();
    let alias = target.parent().unwrap().join("alias");
    symlink("target", &alias).unwrap();

    for (entry, warns) in [
        (alias.display().to_string(), true),
        (target.display().to_string(), false),
        (format!("!{}", alias.display()), false),
    ] {
        let policy = Policy::from_toml(&format!(
            "[policy]\nname='warning-test'\nmode='enforce'\n[policy.exec]\nallow = [{entry:?}]"
        ))
        .unwrap()
        .compile(&SystemResolver::current())
        .unwrap();
        let original = policy.exec.clone();
        let warnings = exec_path_warnings(&policy);
        assert_eq!(warnings.len(), usize::from(warns));
        if warns {
            assert!(warnings[0].contains(&alias.display().to_string()));
            assert!(warnings[0].contains(&target.display().to_string()));
            assert!(warnings[0].contains("target directly"));
            let file = dir.path().join("policy.toml");
            std::fs::write(&file, format!("[policy]\nname='warning-test'\nmode='enforce'\n[policy.exec]\nallow = [{entry:?}]"))
                .unwrap();
            let output = std::process::Command::new(env!("CARGO_BIN_EXE_bee"))
                .args(["validate", "--policy"])
                .arg(file)
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert!(
                stderr.contains(&format!("warning: {}", warnings[0])),
                "{stderr}"
            );
        }
        assert_eq!(policy.exec, original);
    }
}
