use std::process::{Command, Child};
use std::thread::sleep;
use std::time::Duration;
use std::fs;

struct ChildKiller {
    child: Child,
}

impl Drop for ChildKiller {
    fn drop(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}

fn derive_skip_list() -> Vec<String> {
    let openrpc_raw = fs::read("./openrpc.json")
        .expect("Failed to open openrpc.json");

    let openrpc: serde_json::Value = serde_json::from_slice(&openrpc_raw)
        .expect("openrpc.json isn't a valid JSON document");

    let methods = openrpc.get("methods")
        .expect("methods array not found in openrpc.json");

    let methods = methods.as_array()
        .expect("methods is not an array");

    let mut skip_list = Vec::new();

    for method in methods {
        let method = method.as_object()
            .expect("method array should contain objects");

        if !method.contains_key("examples") {
            let name = method.get("name")
               .expect("method object doesn't have a 'name' field");

            let name = name.as_str()
                .expect("method name should be a string");

            skip_list.push(name.to_owned());
        }
    }

    skip_list
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn openrpc_test_cov() {
    // derive skip list from openrpc.json
    let skip_list = derive_skip_list();
    let skip_list = skip_list.join(",");

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
    let mut test_coverage = Command::new("open-rpc-test-coverage");

    test_coverage
        .arg("-s")
        .arg("./openrpc.json")
        .arg("--transport=http")
        .arg("--reporter=console");

    if !skip_list.is_empty() {
        let skip_methods_arg = format!("--skipMethods={}", skip_list);
        test_coverage
            .arg(skip_methods_arg);
    }

    let status = test_coverage.status()
        .expect("failed to start open-rpc-test-coverage: make sure you have it installed.");

    if !status.success() {
        panic!("open-rpc-test-coverage exited with error: {:?}", status);
    }
}