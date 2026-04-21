use std::process::Command;

#[test]
fn test_e2e_policy_compilation() {
    let output = Command::new("cargo")
        .arg("run")
        .arg("--")
        .arg("build")
        .arg("tests/e2e_policy.telos")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success(), "Execution failed: {}", String::from_utf8_lossy(&output.stderr));
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Compilation finished"), "Did not find expected compilation output message:\n{}", stdout);
}

#[test]
fn test_ifc_explicit_leak_fails() {
    let output = Command::new("cargo")
        .arg("run")
        .arg("--")
        .arg("check")
        .arg("tests/ifc_fail.telos")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed");

    // We expect it to FAIL due to an explicit IFC leak
    assert!(!output.status.success(), "Expected compilation to fail precisely on IFC leak syntax");
}

#[test]
fn test_ifc_implicit_leak_fails() {
    let output = Command::new("cargo")
        .arg("run")
        .arg("--")
        .arg("check")
        .arg("tests/ifc_implicit.telos")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed");

    assert!(!output.status.success(), "Expected compilation to fail precisely on Implicit context leak");
}

#[test]
fn test_declassify_pass() {
    let output = Command::new("cargo")
        .arg("run")
        .arg("--")
        .arg("check")
        .arg("tests/declassify_pass.telos")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed");

    assert!(output.status.success(), "Expected declassification pass to succeed. stderr: {}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn test_declassify_fail() {
    let output = Command::new("cargo")
        .arg("run")
        .arg("--")
        .arg("check")
        .arg("tests/declassify_fail.telos")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed");

    assert!(!output.status.success(), "Expected declassification using unwhitelisted algo to fail.");
}
