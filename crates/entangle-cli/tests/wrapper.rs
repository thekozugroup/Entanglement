//! Optional shell wrappers preserve user startup files and command semantics.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

fn entangle(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_entangle"))
        .args(args)
        .env("HOME", home)
        .env("SHELL", "/bin/bash")
        .env_remove("ZDOTDIR")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("ENTANGLE_WRAPPER_ACTIVE")
        .output()
        .unwrap()
}

fn assert_ok(out: &Output) {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn noninteractive_install_opt_in_and_opt_out_persist_across_reinstall() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let examples = root.join("examples");
    let component = root.join("crates/entangle-host/tests/fixtures/hello-pong.wasm");
    assert_ok(&entangle(home, &["init", "--non-interactive"]));
    assert_ok(&entangle(
        home,
        &[
            "plugins",
            "install",
            "hello-world",
            "--catalog",
            examples.to_str().unwrap(),
            "--wasm",
            component.to_str().unwrap(),
            "--no-load",
        ],
    ));
    let package = home.join(".entangle/plugins/hello-world");
    let package = package.to_str().unwrap();
    assert_ok(&entangle(home, &["install", package, "--wrapper"]));
    assert!(std::fs::read_to_string(home.join(".bashrc"))
        .unwrap()
        .contains("# >>> entangle wrapper >>>"));
    assert_ok(&entangle(home, &["install", package, "--no-wrapper"]));
    let opt_out = std::fs::read_to_string(home.join(".entangle/config.toml")).unwrap();
    assert!(opt_out.contains("install = false"));
    assert_ok(&entangle(home, &["install", package]));
    assert_eq!(
        std::fs::read_to_string(home.join(".entangle/config.toml")).unwrap(),
        opt_out
    );
    assert!(!std::fs::read_to_string(home.join(".bashrc"))
        .unwrap()
        .contains("# >>> entangle wrapper >>>"));
}

fn bash(home: &Path, session: Option<&str>) -> Output {
    let mut cmd = Command::new("bash");
    cmd.args(["--noprofile", "--rcfile"])
        .arg(home.join(".bashrc"))
        .args(["-ic", "claude-code 'two words' final"])
        .env("HOME", home)
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", home.join("bin").display()),
        )
        .env_remove("ENTANGLE_WRAPPER_ACTIVE");
    match session {
        Some(value) => {
            cmd.env("ENTANGLE_SESSION_ID", value);
        }
        None => {
            cmd.env_remove("ENTANGLE_SESSION_ID");
        }
    }
    cmd.output().unwrap()
}

#[test]
fn wrapper_warns_passes_arguments_and_exit_and_disable_restores_user_file() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    std::fs::create_dir(home.join("bin")).unwrap();
    let program = home.join("bin/claude-code");
    std::fs::write(&program, "#!/bin/sh\nprintf '<%s>\\n' \"$@\"\nexit 37\n").unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
    let rc = home.join(".bashrc");
    let original = "# existing user content without final newline";
    std::fs::write(&rc, original).unwrap();
    std::fs::write(home.join("config.toml"), "unrelated").unwrap();
    assert_ok(&entangle(home, &["wrapper", "enable", "--shell", "bash"]));
    let installed = std::fs::read_to_string(&rc).unwrap();
    assert_ok(&entangle(home, &["wrapper", "enable", "--shell", "bash"]));
    assert_eq!(std::fs::read_to_string(&rc).unwrap(), installed);
    std::fs::write(&rc, original).unwrap();
    assert_ok(&entangle(home, &["wrapper", "repair", "--shell", "bash"]));
    assert_eq!(std::fs::read_to_string(&rc).unwrap(), installed);
    let result = bash(home, None);
    assert_eq!(result.status.code(), Some(37));
    assert_eq!(result.stdout, b"<two words>\n<final>\n");
    assert!(String::from_utf8_lossy(&result.stderr)
        .contains("claude-code launched outside Entanglement session"));
    let session = bash(home, Some("session"));
    assert_eq!(session.status.code(), Some(37));
    assert!(!String::from_utf8_lossy(&session.stderr).contains("outside Entanglement session"));
    assert_ok(&entangle(home, &["wrapper", "disable"]));
    assert_eq!(std::fs::read_to_string(&rc).unwrap(), original);
    let unwrapped = bash(home, None);
    assert_eq!(unwrapped.status.code(), Some(37));
    assert!(!String::from_utf8_lossy(&unwrapped.stderr).contains("outside Entanglement session"));
    let cfg = std::fs::read_to_string(home.join(".entangle/config.toml")).unwrap();
    assert!(cfg.contains("install = false"));
}

#[test]
fn wrapper_refuses_symlink_and_modified_managed_block_without_clobbering() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let other = home.join("real-rc");
    std::fs::write(&other, "user data").unwrap();
    std::os::unix::fs::symlink(&other, home.join(".bashrc")).unwrap();
    let out = entangle(home, &["wrapper", "enable", "--shell", "bash"]);
    assert!(!out.status.success());
    assert_eq!(std::fs::read_to_string(&other).unwrap(), "user data");
    std::fs::remove_file(home.join(".bashrc")).unwrap();
    assert_ok(&entangle(home, &["wrapper", "enable", "--shell", "bash"]));
    let rc = home.join(".bashrc");
    let modified = std::fs::read_to_string(&rc)
        .unwrap()
        .replace("Optional warning", "User modified warning");
    std::fs::write(&rc, &modified).unwrap();
    let out = entangle(home, &["wrapper", "disable"]);
    assert!(!out.status.success());
    assert_eq!(std::fs::read_to_string(&rc).unwrap(), modified);
    assert!(std::fs::read_to_string(home.join(".entangle/config.toml"))
        .unwrap()
        .contains("install = true"));
}

#[test]
fn disabling_silences_an_already_running_shell_without_changing_forwarding() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    std::fs::create_dir(home.join("bin")).unwrap();
    let program = home.join("bin/claude-code");
    std::fs::write(&program, "#!/bin/sh\nprintf '<%s>\\n' \"$@\"\nexit 37\n").unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_ok(&entangle(home, &["wrapper", "enable", "--shell", "bash"]));
    let cli_dir = Path::new(env!("CARGO_BIN_EXE_entangle")).parent().unwrap();
    let output = Command::new("bash")
        .args(["--noprofile", "--norc", "-c", "source \"$HOME/.bashrc\"; claude-code first; entangle wrapper disable; claude-code second"])
        .env("HOME", home)
        .env("SHELL", "/bin/bash")
        .env_remove("ENTANGLE_SESSION_ID")
        .env_remove("ZDOTDIR")
        .env_remove("XDG_CONFIG_HOME")
        .env("PATH", format!("{}:{}:/usr/bin:/bin", home.join("bin").display(), cli_dir.display()))
        .output().unwrap();
    assert_eq!(output.status.code(), Some(37));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr
            .matches("claude-code launched outside Entanglement session")
            .count(),
        1,
        "{stderr}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("<first>\n") && stdout.contains("<second>\n"),
        "{stdout}"
    );
}

#[test]
fn wrapper_preserves_config_comments_and_other_sections() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    std::fs::create_dir(home.join(".entangle")).unwrap();
    let cfg_path = home.join(".entangle/config.toml");
    std::fs::write(
        &cfg_path,
        "# keep this comment\n[mesh]\ntransports = [] # keep transport comment\n[wrappers]\ninstall = false # keep preference comment\n",
    )
    .unwrap();
    assert_ok(&entangle(home, &["wrapper", "enable", "--shell", "bash"]));
    assert_ok(&entangle(home, &["wrapper", "disable"]));
    let contents = std::fs::read_to_string(cfg_path).unwrap();
    assert!(contents.contains("# keep this comment"));
    assert!(contents.contains("transports = [] # keep transport comment"));
    assert!(contents.contains("install = false # keep preference comment"));
}

#[test]
#[ignore = "requires zsh; run explicitly when the shell is installed"]
fn zsh_wrapper_preserves_arguments_and_exit() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    std::fs::create_dir(home.join("bin")).unwrap();
    let program = home.join("bin/claude-code");
    std::fs::write(&program, "#!/bin/sh\nprintf '<%s>\\n' \"$@\"\nexit 37\n").unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_ok(&entangle(home, &["wrapper", "enable", "--shell", "zsh"]));
    let output = Command::new("zsh")
        .args(["-ic", "claude-code 'two words' final"])
        .env("HOME", home)
        .env("ZDOTDIR", home)
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", home.join("bin").display()),
        )
        .env_remove("ENTANGLE_SESSION_ID")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(37));
    assert_eq!(output.stdout, b"<two words>\n<final>\n");
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("claude-code launched outside Entanglement session"));
}

#[test]
#[ignore = "requires fish; set ENTANGLE_FISH to its executable and run explicitly"]
fn fish_wrapper_forwards_and_warns_when_sourced() {
    let fish = std::env::var_os("ENTANGLE_FISH").unwrap_or_else(|| "fish".into());
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    std::fs::create_dir(home.join("bin")).unwrap();
    let program = home.join("bin/claude-code");
    std::fs::write(&program, "#!/bin/sh\nprintf '<%s>\\n' \"$@\"\nexit 37\n").unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_ok(&entangle(home, &["wrapper", "enable", "--shell", "fish"]));
    let run = |session: Option<&str>| {
        let mut command = Command::new(&fish);
        command.args(["--no-config", "-c", "source \"$HOME/.config/fish/conf.d/entangle-wrapper.fish\"; claude-code 'two words' final"])
            .env("HOME", home)
            .env("PATH", format!("{}:/usr/bin:/bin", home.join("bin").display()));
        if let Some(value) = session {
            command.env("ENTANGLE_SESSION_ID", value);
        } else {
            command.env_remove("ENTANGLE_SESSION_ID");
        }
        command.output().unwrap()
    };
    let outside = run(None);
    assert_eq!(outside.status.code(), Some(37));
    assert_eq!(outside.stdout, b"<two words>\n<final>\n");
    assert!(String::from_utf8_lossy(&outside.stderr)
        .contains("claude-code launched outside Entanglement session"));
    let inside = run(Some("session"));
    assert_eq!(inside.status.code(), Some(37));
    assert!(!String::from_utf8_lossy(&inside.stderr).contains("outside Entanglement session"));
}

#[test]
fn doctor_fails_when_opted_in_wrapper_was_not_loaded_and_agent_is_on_path() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    std::fs::create_dir(home.join("bin")).unwrap();
    let program = home.join("bin/claude-code");
    std::fs::write(&program, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_ok(&entangle(home, &["wrapper", "enable", "--shell", "bash"]));
    let out = Command::new(env!("CARGO_BIN_EXE_entangle"))
        .arg("doctor")
        .env("HOME", home)
        .env_remove("ENTANGLE_WRAPPER_ACTIVE")
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", home.join("bin").display()),
        )
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).contains("shadowed"));
}
