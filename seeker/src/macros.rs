macro_rules! retry_timeout {
    ($timeout: expr, $retries: expr, $fut: expr) => {
        async {
            let mut retries: usize = $retries;
            loop {
                let ret = timeout($timeout, $fut).await;
                match ret {
                    v @ Ok(_) => break v,
                    e @ Err(_) => {
                        if retries <= 0 {
                            break e;
                        }
                    }
                }
                retries -= 1;
            }
        }
    };
}

macro_rules! retry_timeout_next_candidate {
    ($timeout: expr, $retries: expr, $fut: expr, $chooser: expr) => {
        async {
            let mut tries: usize = 10;
            loop {
                match retry_timeout!($timeout, $retries, $fut).await {
                    v @ Ok(_) => break v,
                    e @ Err(_) => {
                        if tries <= 0 {
                            break e;
                        }
                        if $chooser.next_candidate().is_none() {
                            break e;
                        }
                    }
                }
                tries -= 1;
            }
        }
    };
}
