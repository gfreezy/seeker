use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, bail, ensure};
use flate2::read::GzDecoder;
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const LATEST_RELEASE_URL: &str = "https://api.github.com/repos/gfreezy/seeker/releases/latest";
const MAX_ARCHIVE_SIZE: u64 = 128 * 1024 * 1024;
const MAX_BINARY_SIZE: u64 = 256 * 1024 * 1024;

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
    size: u64,
    digest: Option<String>,
}

pub fn upgrade() -> anyhow::Result<()> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .user_agent(concat!("seeker/", env!("CARGO_PKG_VERSION")))
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_global(Some(Duration::from_secs(120)))
        .build()
        .into();
    upgrade_from(
        &agent,
        LATEST_RELEASE_URL,
        env!("CARGO_PKG_VERSION"),
        env!("SEEKER_BUILD_TARGET"),
        &std::env::current_exe().context("Locate the current executable")?,
    )
}

fn upgrade_from(
    agent: &ureq::Agent,
    release_url: &str,
    current_version: &str,
    build_target: &str,
    executable: &Path,
) -> anyhow::Result<()> {
    let target = release_target(build_target)?;
    println!("Checking for the latest Seeker release (current: {current_version})...");
    let release: Release = agent
        .get(release_url)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .call()
        .context("Fetch the latest GitHub release (check connectivity and GitHub API rate limits)")?
        .body_mut()
        .read_json()
        .context("Read GitHub release metadata")?;
    ensure!(
        !release.draft && !release.prerelease,
        "GitHub did not return a stable, published release"
    );
    let latest = Version::parse(
        release
            .tag_name
            .strip_prefix('v')
            .unwrap_or(&release.tag_name),
    )
    .context("Parse the latest release version")?;
    let current = Version::parse(current_version).context("Parse the current version")?;
    if latest <= current {
        println!(
            "Seeker {current_version} is already up to date (latest release: {}).",
            release.tag_name
        );
        return Ok(());
    }

    let asset_name = format!("seeker-{target}.tar.gz");
    let asset = release
        .assets
        .iter()
        .find(|asset| asset.name == asset_name)
        .with_context(|| {
            format!(
                "Release {} has no {asset_name}; its build may still be in progress. Try again later",
                release.tag_name
            )
        })?;
    println!("Downloading {} ({asset_name})...", release.tag_name);
    let archive = download_archive(agent, asset)?;
    install_archive(archive, executable)?;
    println!(
        "Upgraded Seeker from {current_version} to {} at {}. Restart any running Seeker process to use the new version.",
        release.tag_name,
        executable.display()
    );
    Ok(())
}

fn release_target(build_target: &str) -> anyhow::Result<&str> {
    // Linux releases are statically linked with musl, including upgrades from GNU builds.
    match build_target {
        "aarch64-apple-darwin"
        | "x86_64-apple-darwin"
        | "aarch64-unknown-linux-musl"
        | "x86_64-unknown-linux-musl"
        | "armv5te-unknown-linux-musleabi"
        | "armv7-unknown-linux-musleabi" => Ok(build_target),
        "aarch64-unknown-linux-gnu" => Ok("aarch64-unknown-linux-musl"),
        "x86_64-unknown-linux-gnu" => Ok("x86_64-unknown-linux-musl"),
        _ => bail!("Automatic upgrades are not supported for build target {build_target}"),
    }
}

fn download_archive(agent: &ureq::Agent, asset: &Asset) -> anyhow::Result<File> {
    let expected = asset
        .digest
        .as_deref()
        .and_then(|digest| digest.strip_prefix("sha256:"))
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|c| c.is_ascii_hexdigit()))
        .context("Release asset has no valid SHA-256 digest; refusing to install it")?;
    ensure!(
        asset.size > 0 && asset.size <= MAX_ARCHIVE_SIZE,
        "Release archive has an invalid or excessive size"
    );
    let response = agent
        .get(&asset.browser_download_url)
        .header("Accept", "application/octet-stream")
        .call()
        .context("Download the release archive")?;
    let mut reader = response.into_body().into_reader().take(asset.size + 1);
    let mut archive = tempfile::tempfile().context("Create a temporary archive")?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 16 * 1024];
    let mut size = 0;
    loop {
        let count = reader
            .read(&mut buffer)
            .context("Read the release archive")?;
        if count == 0 {
            break;
        }
        archive.write_all(&buffer[..count])?;
        hasher.update(&buffer[..count]);
        size += count as u64;
    }
    ensure!(
        size == asset.size,
        "Release archive size does not match GitHub metadata"
    );
    let actual = format!("{:x}", hasher.finalize());
    ensure!(
        actual.eq_ignore_ascii_case(expected),
        "Release archive SHA-256 checksum mismatch; the current executable was not changed"
    );
    archive.rewind()?;
    Ok(archive)
}

fn install_archive(reader: impl Read, executable: &Path) -> anyhow::Result<()> {
    // Resolve symlinks so launchers keep pointing at the same executable path.
    let executable = executable
        .canonicalize()
        .context("Resolve the executable path")?;
    let parent = executable
        .parent()
        .context("Locate the executable directory")?;
    let permissions = std::fs::metadata(&executable)?.permissions();
    // Staging beside the executable keeps the final rename on the same filesystem.
    let mut binary = tempfile::Builder::new()
        .prefix(".seeker-upgrade-")
        .tempfile_in(parent)
        .with_context(|| {
            format!(
                "Create a replacement in {}; check directory permissions or run `sudo seeker upgrade`",
                parent.display()
            )
        })?;
    let mut archive = tar::Archive::new(GzDecoder::new(reader));
    let mut found = false;
    for entry in archive.entries().context("Read the release archive")? {
        let mut entry = entry.context("Read an archive entry")?;
        if entry.path()?.as_ref() != Path::new("seeker") {
            continue;
        }
        ensure!(!found, "Release archive contains multiple seeker binaries");
        ensure!(
            entry.header().entry_type().is_file(),
            "Archived seeker is not a regular file"
        );
        ensure!(
            entry.size() > 0 && entry.size() <= MAX_BINARY_SIZE,
            "Archived seeker binary has an invalid or excessive size"
        );
        io::copy(&mut entry, &mut binary).context("Extract the seeker binary")?;
        found = true;
    }
    ensure!(found, "Release archive does not contain a seeker binary");
    binary
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(permissions.mode() & 0o777))?;
    binary
        .as_file()
        .sync_all()
        .context("Sync the replacement executable")?;
    // Rename replaces the directory entry without writing to an executing inode.
    binary
        .persist(&executable)
        .map_err(|error| error.error)
        .with_context(|| {
            format!(
                "Replace {}; check directory permissions",
                executable.display()
            )
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::os::unix::fs::symlink;
    use std::thread;

    fn archive(entries: &[(&str, tar::EntryType, &[u8])]) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let mut builder = tar::Builder::new(encoder);
        for (name, kind, content) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(*kind);
            header.set_mode(0o755);
            header.set_size(content.len() as u64);
            if kind.is_symlink() {
                header.set_link_name("other").unwrap();
            }
            builder.append_data(&mut header, name, *content).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn executable(directory: &Path) -> std::path::PathBuf {
        let path = directory.join("seeker");
        std::fs::write(&path, b"old binary").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o751)).unwrap();
        path
    }

    // Exercise the real HTTP client, metadata decoding, download and installation locally.
    fn serve_release(
        tag: &str,
        asset: Option<(&[u8], String)>,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let mut release = serde_json::json!({
            "tag_name": tag,
            "draft": false,
            "prerelease": false,
            "assets": [],
        });
        let mut responses = Vec::new();
        if let Some((archive, digest)) = asset {
            release["assets"] = serde_json::json!([{
                "name": "seeker-aarch64-apple-darwin.tar.gz",
                "browser_download_url": format!("{base}/archive"),
                "size": archive.len(),
                "digest": digest,
            }]);
            responses.push(("/archive", archive.to_vec()));
        }
        responses.insert(0, ("/latest", serde_json::to_vec(&release).unwrap()));
        let server = thread::spawn(move || {
            for (path, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = BufReader::new(&mut stream);
                let mut line = String::new();
                request.read_line(&mut line).unwrap();
                assert_eq!(line.split_whitespace().nth(1), Some(path));
                loop {
                    line.clear();
                    request.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                }
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .unwrap();
                stream.write_all(&body).unwrap();
            }
        });
        (format!("{base}/latest"), server)
    }

    fn test_agent() -> ureq::Agent {
        ureq::Agent::config_builder()
            .proxy(None)
            .timeout_global(Some(Duration::from_secs(5)))
            .build()
            .into()
    }

    #[test]
    fn upgrades_from_github_metadata_and_preserves_executable_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let executable = executable(directory.path());
        let archive = archive(&[("seeker", tar::EntryType::Regular, b"new binary")]);
        let digest = format!("sha256:{:x}", Sha256::digest(&archive));
        let (url, server) = serve_release("v2.0.0", Some((&archive, digest)));
        upgrade_from(
            &test_agent(),
            &url,
            "1.0.0",
            "aarch64-apple-darwin",
            &executable,
        )
        .unwrap();
        server.join().unwrap();
        assert_eq!(std::fs::read(&executable).unwrap(), b"new binary");
        assert_eq!(
            std::fs::metadata(&executable).unwrap().permissions().mode() & 0o777,
            0o751
        );
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn checksum_mismatch_leaves_the_original_executable_untouched() {
        let directory = tempfile::tempdir().unwrap();
        let executable = executable(directory.path());
        let archive = archive(&[("seeker", tar::EntryType::Regular, b"new binary")]);
        let (url, server) = serve_release(
            "v2.0.0",
            Some((&archive, format!("sha256:{}", "0".repeat(64)))),
        );
        let error = upgrade_from(
            &test_agent(),
            &url,
            "1.0.0",
            "aarch64-apple-darwin",
            &executable,
        )
        .unwrap_err();
        server.join().unwrap();
        assert!(error.to_string().contains("checksum mismatch"));
        assert_eq!(std::fs::read(&executable).unwrap(), b"old binary");
    }

    #[test]
    fn current_or_newer_versions_do_not_download_or_replace_anything() {
        for current in ["2.0.0", "3.0.0"] {
            let directory = tempfile::tempdir().unwrap();
            let executable = executable(directory.path());
            let (url, server) = serve_release("v2.0.0", None);
            upgrade_from(
                &test_agent(),
                &url,
                current,
                "aarch64-apple-darwin",
                &executable,
            )
            .unwrap();
            server.join().unwrap();
            assert_eq!(std::fs::read(&executable).unwrap(), b"old binary");
        }
    }

    #[test]
    fn missing_platform_asset_leaves_the_original_executable_untouched() {
        let directory = tempfile::tempdir().unwrap();
        let executable = executable(directory.path());
        let (url, server) = serve_release("v2.0.0", None);
        let error = upgrade_from(
            &test_agent(),
            &url,
            "1.0.0",
            "aarch64-apple-darwin",
            &executable,
        )
        .unwrap_err();
        server.join().unwrap();
        assert!(
            error
                .to_string()
                .contains("has no seeker-aarch64-apple-darwin.tar.gz")
        );
        assert_eq!(std::fs::read(&executable).unwrap(), b"old binary");
    }

    #[test]
    fn invalid_archives_leave_the_original_executable_and_directory_untouched() {
        let archives = [
            b"invalid gzip".to_vec(),
            archive(&[("README", tar::EntryType::Regular, b"no executable")]),
            archive(&[("seeker", tar::EntryType::Symlink, b"")]),
            archive(&[("seeker", tar::EntryType::Regular, b"")]),
            archive(&[("nested/seeker", tar::EntryType::Regular, b"wrong path")]),
            archive(&[
                ("seeker", tar::EntryType::Regular, b"first"),
                ("seeker", tar::EntryType::Regular, b"second"),
            ]),
        ];
        for archive in archives {
            let directory = tempfile::tempdir().unwrap();
            let executable = executable(directory.path());
            assert!(install_archive(archive.as_slice(), &executable).is_err());
            assert_eq!(std::fs::read(&executable).unwrap(), b"old binary");
            assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
        }
    }

    #[test]
    fn replaces_the_symlink_target_and_only_extracts_the_binary() {
        let directory = tempfile::tempdir().unwrap();
        let executable = executable(directory.path());
        let launcher = directory.path().join("launcher");
        symlink(&executable, &launcher).unwrap();
        let archive = archive(&[
            ("other", tar::EntryType::Regular, b"ignored"),
            ("seeker", tar::EntryType::Regular, b"new binary"),
        ]);
        install_archive(archive.as_slice(), &launcher).unwrap();
        assert!(launcher.is_symlink());
        assert_eq!(std::fs::read(&launcher).unwrap(), b"new binary");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 2);
    }

    #[test]
    fn selects_published_platforms_and_linux_musl_fallbacks() {
        for target in [
            "aarch64-apple-darwin",
            "x86_64-apple-darwin",
            "aarch64-unknown-linux-musl",
            "x86_64-unknown-linux-musl",
            "armv5te-unknown-linux-musleabi",
            "armv7-unknown-linux-musleabi",
        ] {
            assert_eq!(release_target(target).unwrap(), target);
        }
        assert_eq!(
            release_target("x86_64-unknown-linux-gnu").unwrap(),
            "x86_64-unknown-linux-musl"
        );
        assert_eq!(
            release_target("aarch64-unknown-linux-gnu").unwrap(),
            "aarch64-unknown-linux-musl"
        );
        assert!(release_target("x86_64-unknown-freebsd").is_err());
    }
}
