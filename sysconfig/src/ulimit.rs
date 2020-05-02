use crate::command::run_cmd;

pub fn ulimit(opt: &str, value: &str) {
    let _ = run_cmd("ulimit", &[opt, value]);
}
