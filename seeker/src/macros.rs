macro_rules! retry_timeout {
    ($timeout: expr, $retries: expr, $fut: expr) => {
        async {
            let mut retries: usize = $retries;
            loop {
                let ret = tokio::time::timeout($timeout, $fut).await;
                match ret {
                    Ok(v) => break v,
                    Err(_) => {
                        tracing::warn!("retry_timeout: {}", $retries - retries);
                        if retries <= 0 {
                            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"));
                        }
                    }
                }
                retries -= 1;
            }
        }
    };
}
