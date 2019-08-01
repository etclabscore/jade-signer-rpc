use std::process::{Command, Child};
use std::thread::sleep;
use std::time::Duration;

struct ChildKiller {
    child: Child,
}

impl Drop for ChildKiller {
    fn drop(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn openrpc_test_cov() {
    // Build server
    let status = Command::new("cargo")
        .arg("build")
        .arg("--features")
        .arg("fixed-seed")
        .status()
        .expect("failed to start server");

    if !status.success() {
        panic!("failed to build jade-signer");
    }

    // Start server
    let mut server = Command::new("cargo")
        .arg("run")
        .arg("--features")
        .arg("fixed-seed")
        .arg("--")
        .arg("server")
        .spawn()
        .expect("failed to start server");

    let guard = ChildKiller { child: server };

    // Wait for server to spin-up
    sleep(Duration::from_secs(5));

    // Run open-rpc-test-coverage tool
    let status = Command::new("open-rpc-test-coverage")
        .arg("-s")
        .arg("./openrpc.json")
        .arg("--transport=http")
        .arg("--reporter=console")
        .status()
        .expect("failed to start open-rpc-test-coverage: make sure you have it installed.");

    if !status.success() {
        panic!("open-rpc-test-coverage exited with error: {:?}", status);
    }
}