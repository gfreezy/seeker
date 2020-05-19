use file_rotate::{FileRotate, RotationMode};
use std::error::Error;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

#[derive(Clone)]
struct TracingWriter {
    file_rotate: Arc<Mutex<FileRotate>>,
}

impl TracingWriter {
    fn new(file_rotate: Arc<Mutex<FileRotate>>) -> Self {
        TracingWriter { file_rotate }
    }
}

impl io::Write for TracingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut guard = self.file_rotate.lock().unwrap();
        guard.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut guard = self.file_rotate.lock().unwrap();
        guard.flush()
    }
}

pub fn setup_logger(log_path: Option<&str>) -> Result<(), Box<dyn Error>> {
    let env_filter = EnvFilter::new("seeker=trace")
        .add_directive("dnsserver=debug".parse()?)
        .add_directive("seeker=trace".parse()?)
        .add_directive("sysconfig=info".parse()?)
        .add_directive("tun_nat=info".parse()?);

    if let Some(log_path) = log_path {
        if let Some(path) = PathBuf::from(log_path).parent() {
            std::fs::create_dir_all(path)?;
        }
        let logger = Arc::new(Mutex::new(FileRotate::new(
            log_path,
            RotationMode::Lines(100_000),
            20,
        )));
        let my_subscriber = FmtSubscriber::builder()
            .with_env_filter(env_filter)
            .with_ansi(false)
            .with_writer(move || TracingWriter::new(logger.clone()))
            .finish();
        tracing::subscriber::set_global_default(my_subscriber)
            .expect("setting tracing default failed");
    } else {
        let subscriber = FmtSubscriber::builder()
            .with_env_filter(env_filter)
            .compact()
            .finish();

        tracing::subscriber::set_global_default(subscriber)
            .expect("setting tracing default failed");
    };

    #[cfg(debug_assertions)]
    {
        // only for #[cfg]
        use parking_lot::deadlock;
        use std::thread;
        use std::time::Duration;

        // Create a background thread which checks for deadlocks every 10s
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(10));
            let deadlocks = deadlock::check_deadlock();
            if deadlocks.is_empty() {
                continue;
            }

            eprintln!("{} deadlocks detected", deadlocks.len());
            for (i, threads) in deadlocks.iter().enumerate() {
                eprintln!("Deadlock #{}", i);
                for t in threads {
                    eprintln!("Thread Id {:#?}", t.thread_id());
                    eprintln!("{:#?}", t.backtrace());
                }
            }
        });
    } // only for #[cfg]
    Ok(())
}
