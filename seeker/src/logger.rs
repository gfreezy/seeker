use file_rotate::{suffix::AppendTimestamp, FileRotate};
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
#[cfg(feature = "tracing-chrome")]
use tracing_chrome::{ChromeLayerBuilder, FlushGuard};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, Layer, Registry};

#[derive(Clone)]
struct TracingWriter {
    file_rotate: Arc<Mutex<FileRotate<AppendTimestamp>>>,
}

impl TracingWriter {
    fn new(file_rotate: Arc<Mutex<FileRotate<AppendTimestamp>>>) -> Self {
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

pub(crate) struct LoggerGuard {
    #[cfg(feature = "tracing-chrome")]
    _chrome_layer_guard: Option<FlushGuard>,
}

pub(crate) fn setup_logger(log_path: Option<&str>, trace: bool) -> anyhow::Result<LoggerGuard> {
    let env_filter = EnvFilter::new("seeker=trace")
        .add_directive("dnsserver=debug".parse()?)
        .add_directive("sysconfig=info".parse()?)
        .add_directive("config=info".parse()?)
        .add_directive("tun_nat=info".parse()?);

    let _chrome_layer_guard = if let Some(log_path) = log_path {
        if let Some(path) = PathBuf::from(log_path).parent() {
            std::fs::create_dir_all(path)?;
        }
        let logger = Arc::new(Mutex::new(FileRotate::new(
            log_path,
            AppendTimestamp::default(file_rotate::suffix::FileLimit::MaxFiles(10)),
            file_rotate::ContentLimit::Bytes(10_000_000),
            file_rotate::compression::Compression::None,
            #[cfg(unix)]
            None,
        )));

        if trace {
            let fmt_layer = tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(move || TracingWriter::new(logger.clone()))
                .and_then(env_filter);

            #[cfg(feature = "tracing-chrome")]
            {
                let (chrome_layer, guard) = ChromeLayerBuilder::new()
                    .include_args(true)
                    .trace_style(tracing_chrome::TraceStyle::Async)
                    .build();

                let registry = Registry::default().with(fmt_layer).with(chrome_layer);

                tracing::subscriber::set_global_default(registry)
                    .expect("setting tracing default failed");
                Some(guard)
            }

            #[cfg(not(feature = "tracing-chrome"))]
            {
                let registry = Registry::default().with(fmt_layer);

                tracing::subscriber::set_global_default(registry)
                    .expect("setting tracing default failed");
                None::<()>
            }
        } else {
            let fmt_layer = tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_file(true)
                .with_line_number(true)
                .with_writer(move || TracingWriter::new(logger.clone()))
                .and_then(env_filter);
            let registry = Registry::default().with(fmt_layer);

            tracing::subscriber::set_global_default(registry)
                .expect("setting tracing default failed");
            None
        }
    } else {
        None
    };

    let guard = LoggerGuard {
        #[cfg(feature = "tracing-chrome")]
        _chrome_layer_guard: _chrome_layer_guard,
    };

    // #[cfg(debug_assertions)]
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
                eprintln!("Deadlock #{i}");
                for t in threads {
                    eprintln!("Thread Id {:#?}", t.thread_id());
                    eprintln!("{:#?}", t.backtrace());
                }
            }
        });
    } // only for #[cfg]
    Ok(guard)
}
