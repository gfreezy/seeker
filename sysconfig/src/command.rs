use std::process::Command;
use tracing::info;

pub fn run_cmd(cmd: &str, args: &[&str]) -> String {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .unwrap_or_else(|_| panic!("run cmd failed: {cmd}, args: {args:?}"));
    let stdout = std::str::from_utf8(&output.stdout).expect("utf8");
    let stderr = std::str::from_utf8(&output.stderr).expect("utf8");
    info!("cmd: {cmd}, args: {:?}", args);
    info!("stdout: {}", stdout);
    info!("stderr: {}", stderr);

    if !output.status.success() {
        panic!(
            "{} {}\nstdout: {}\nstderr: {}",
            cmd,
            args.join(" "),
            stdout,
            stderr
        );
    }
    stdout.to_string()
}
