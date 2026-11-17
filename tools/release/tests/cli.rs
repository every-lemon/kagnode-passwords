// SPDX-License-Identifier: AGPL-3.0-only
use std::process::Command;
const BIN: &str = env!("CARGO_BIN_EXE_kagnode-passwords-release-candidate");
#[test]
fn help_is_non_mutating_and_labels_the_boundary() {
    let out = Command::new(BIN).arg("--help").output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("never publishes or installs"));
    assert!(text.contains("EXTERNAL_PUBLIC_KEY"));
}
#[test]
fn rejected_arguments_do_not_echo_sensitive_values() {
    let out = Command::new(BIN)
        .args(["unknown", "synthetic-do-not-echo-argument"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!String::from_utf8_lossy(&out.stderr).contains("synthetic-do-not-echo-argument"));
}
