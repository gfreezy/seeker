use std::io;

pub fn set_rlimit_no_file(no: u64) -> io::Result<()> {
    #[cfg(not(target_arch = "arm"))]
    let rlim = libc::rlimit {
        rlim_cur: no,
        rlim_max: no,
    };
    #[cfg(target_arch = "arm")]
    let rlim = libc::rlimit {
        rlim_cur: no as u32,
        rlim_max: no as u32,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) };
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn get_rlimit_no_file() -> io::Result<libc::rlimit> {
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let ret = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) };
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(rlim)
}
