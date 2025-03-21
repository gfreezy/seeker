use std::path::PathBuf;
use std::time::Duration;

use notify_debouncer_mini::notify::{RecommendedWatcher, RecursiveMode};
use notify_debouncer_mini::{DebounceEventHandler, Debouncer, new_debouncer};

pub fn watch_config<F: DebounceEventHandler + Send>(
    config_path: PathBuf,
    action: F,
) -> Debouncer<RecommendedWatcher> {
    let mut debouncer =
        new_debouncer(Duration::from_secs(1), action).expect("create debouncer error");

    debouncer
        .watcher()
        .watch(&config_path, RecursiveMode::Recursive)
        .expect("watch path error");

    debouncer
}
