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
    let mut server = Command::new("cargo")
        .arg("run")
        .arg("--")
        .arg("server")
        .spawn()
        .expect("failed to start server");

    let guard = ChildKiller { child: server };

    sleep(Duration::from_secs(1));

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