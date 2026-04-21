use std::process::Command;

#[test]
fn test_e2e_policy_compilation() {
    // We execute `cargo run -- tests/e2e_policy.telos` from within the root level of `telosc`
    let output = Command::new("cargo")
        .arg("run")
        .arg("--")
        .arg("build")
        .arg("tests/e2e_policy.telos")
        // Use CARGO_MANIFEST_DIR to ensure it is always executed from the crate root
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success(), "Execution failed: {}", String::from_utf8_lossy(&output.stderr));
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Compilation finished"), "Did not find expected compilation output message:\n{}", stdout);
}
