macro_rules! retry_timeout {
    ($timeout: expr, $retries: expr, $fut: expr) => {
        async {
            let mut retries: usize = $retries;
            loop {
                let ret = async_std::io::timeout($timeout, $fut).await;
                match ret {
                    v @ Ok(_) => break v,
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                        tracing::warn!("retry_timeout: {}", $retries - retries);
                        if retries <= 0 {
                            return Err(e);
                        }
                    }
                    e => {
                        break e;
                    }
                }
                retries -= 1;
            }
        }
    };
}
