// SPDX-License-Identifier: AGPL-3.0-only
//! Local source-data candidates. No publisher, installer, native activation or trust bootstrap.
use anyhow::{Context, Result, bail, ensure};
use flate2::{Compression, GzBuilder};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use tar::{Builder, Header};
use zeroize::Zeroizing;
mod product;
const MAX_FILE: u64 = 8 * 1024 * 1024;
const MAX_TOTAL: u64 = 64 * 1024 * 1024;
const MAX_FILES: usize = 2048;
const MAX_MANIFEST: u64 = 64 * 1024;
const MANIFEST: &str = "release-manifest.json";
const SIGNATURE: &str = "release-manifest.sig";
const PUBLIC: &str = "release-public.pem";
const SUMS: &str = "SHA256SUMS";
const DER_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    pub repository: String,
    pub source_repository: String,
    pub product_version: String,
    pub source_commit: String,
    pub source_tree: String,
    pub epoch: u64,
    pub channel: String,
    pub payload_kind: String,
    pub qualification: String,
    pub trusted_public_key_sha256: String,
    pub assets: Vec<Asset>,
}
struct Source {
    root: PathBuf,
    head: String,
    tree: String,
    epoch: u64,
    version: String,
    files: Vec<(String, u32, Vec<u8>)>,
}
struct Candidate {
    manifest: Manifest,
    raw: Vec<u8>,
    archive: Vec<u8>,
}
fn hash(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}
fn valid_sha(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn relative(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 200
        && !s.contains('\\')
        && !s.starts_with('/')
        && !s.ends_with('/')
        && s.split('/').all(|p| {
            !p.is_empty()
                && p != "."
                && p != ".."
                && p.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
        })
}
fn regular(path: &Path, cap: u64) -> Result<(Vec<u8>, fs::Metadata)> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .context("Cannot open bounded regular input")?;
    let before = f.metadata()?;
    ensure!(
        before.is_file() && before.len() <= cap && before.nlink() == 1,
        "Input is not an independent bounded regular file"
    );
    let mut bytes = Vec::new();
    (&mut f).take(cap + 1).read_to_end(&mut bytes)?;
    let after = f.metadata()?;
    let named = fs::symlink_metadata(path)?;
    ensure!(
        bytes.len() as u64 <= cap && same_file(&before, &after) && same_file(&after, &named),
        "Input changed during read"
    );
    Ok((bytes, before))
}
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
        && a.nlink() == b.nlink()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.mode() == b.mode()
}
fn directory(path: &Path) -> Result<PathBuf> {
    ensure!(
        fs::symlink_metadata(path)?.is_dir()
            && !fs::symlink_metadata(path)?.file_type().is_symlink(),
        "Expected a real directory"
    );
    Ok(fs::canonicalize(path)?)
}
fn clean_env(c: &mut Command) {
    c.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/nonexistent")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("OPENSSL_CONF", "/dev/null")
        .env("LC_ALL", "C");
}

fn engine(mut c: Command, input: Option<&[u8]>, cap: usize) -> Result<Vec<u8>> {
    clean_env(&mut c);
    c.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::null());
    let mut child = c.spawn().context("Cannot start fixed engine")?;
    if let Some(data) = input {
        ensure!(data.len() <= 1024, "Engine input exceeds bound");
        child
            .stdin
            .take()
            .context("Engine input pipe missing")?
            .write_all(data)?;
    }
    let end = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait()? {
            ensure!(status.success(), "Fixed engine refused input");
            let mut out = Vec::new();
            child
                .stdout
                .take()
                .context("Engine output pipe missing")?
                .take(cap as u64 + 1)
                .read_to_end(&mut out)?;
            ensure!(out.len() <= cap, "Engine output exceeds bound");
            return Ok(out);
        }
        if Instant::now() >= end {
            let _ = child.kill();
            let _ = child.wait();
            bail!("Fixed engine timed out");
        }
        thread::sleep(Duration::from_millis(10));
    }
}
fn git(root: &Path, args: &[&str], cap: usize) -> Result<Vec<u8>> {
    // Git may write a source blob larger than a pipe. Spool its bounded output to an
    // anonymous temporary file instead of waiting with an undrained stdout pipe.
    let out = tempfile::tempfile()?;
    let reader = out.try_clone()?;
    let mut c = Command::new("/usr/bin/git");
    clean_env(&mut c);
    c.args([
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-C",
    ])
    .arg(root)
    .args(args)
    .stdin(Stdio::null())
    .stdout(Stdio::from(out))
    .stderr(Stdio::null());
    let mut child = c.spawn()?;
    let end = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait()? {
            ensure!(status.success(), "Git refused source input");
            break;
        }
        if reader.metadata()?.len() > cap as u64 || Instant::now() >= end {
            let _ = child.kill();
            let _ = child.wait();
            bail!("Git source command exceeded its bound");
        }
        thread::sleep(Duration::from_millis(10));
    }
    ensure!(
        reader.metadata()?.len() <= cap as u64,
        "Git source output exceeds bound"
    );
    use std::io::{Seek, SeekFrom};
    let mut reader = reader;
    reader.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    reader.take(cap as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= cap, "Git source output exceeds bound");
    Ok(bytes)
}
fn git_text(root: &Path, args: &[&str]) -> Result<String> {
    Ok(String::from_utf8(git(root, args, MAX_MANIFEST as usize)?)?
        .trim()
        .to_owned())
}
fn repository(root: &Path) -> Result<PathBuf> {
    let root = directory(root)?;
    let owner = unsafe { libc::geteuid() };
    ensure!(
        fs::metadata(&root)?.uid() == owner && fs::metadata(&root)?.mode() & 0o022 == 0,
        "Source root must be caller-owned and not shared writable"
    );
    ensure!(
        root.join(".git").is_dir()
            && !fs::symlink_metadata(root.join(".git"))?
                .file_type()
                .is_symlink(),
        "Only independent direct-Git-directory checkouts are supported"
    );
    ensure!(
        !root.join(".git/objects/info/alternates").exists(),
        "Alternate Git object stores are unsupported"
    );
    let config = root.join(".git/config");
    let (_, config_meta) = regular(&config, MAX_MANIFEST)?;
    let git_meta = fs::metadata(root.join(".git"))?;
    ensure!(
        config_meta.uid() == owner
            && config_meta.mode() & 0o022 == 0
            && git_meta.uid() == owner
            && git_meta.mode() & 0o022 == 0,
        "Git directory/configuration must remain caller-controlled"
    );
    let mut c = Command::new("/usr/bin/git");
    clean_env(&mut c);
    c.current_dir("/")
        .args(["config", "--no-includes", "--file"])
        .arg(&config)
        .args(["--null", "--list"]);
    let raw = engine(c, None, MAX_MANIFEST as usize)?;
    for row in raw.split(|x| *x == 0).filter(|x| !x.is_empty()) {
        let row = String::from_utf8(row.to_vec())?;
        let (key, value) = row
            .split_once('\n')
            .context("Invalid Git configuration record")?;
        let allowed = matches!(
            key,
            "core.repositoryformatversion"
                | "core.filemode"
                | "core.bare"
                | "core.logallrefupdates"
                | "core.ignorecase"
                | "core.precomposeunicode"
                | "user.name"
                | "user.email"
                | "remote.origin.url"
                | "remote.origin.fetch"
                | "gc.auto"
        ) || key.starts_with("branch.")
            && (key.ends_with(".remote") || key.ends_with(".merge"));
        ensure!(allowed, "Unsupported Git configuration key");
        if key == "gc.auto" {
            ensure!(value == "0", "Only disabled automatic Git GC is supported");
        }
        if key == "remote.origin.url" {
            ensure!(
                (value == format!("https://github.com/{}.git", product::SOURCE_REPOSITORY)
                    || value == format!("https://github.com/{}", product::SOURCE_REPOSITORY)),
                "Unexpected Git source remote"
            );
        }
        if key == "core.bare" {
            ensure!(value == "false", "Bare source worktrees are unsupported");
        }
        if key == "remote.origin.fetch" {
            ensure!(
                value == "+refs/heads/*:refs/remotes/origin/*",
                "Unexpected source fetch policy"
            );
        }
    }
    Ok(root)
}
fn unchanged(root: &Path, head: &str) -> Result<()> {
    ensure!(
        git_text(root, &["rev-parse", "HEAD"])? == head,
        "Source HEAD changed"
    );
    ensure!(
        git(
            root,
            &["status", "--porcelain=v1", "--untracked-files=all"],
            MAX_MANIFEST as usize
        )?
        .is_empty(),
        "Source checkout must be completely clean"
    );
    Ok(())
}
fn snapshot(root: &Path) -> Result<Source> {
    let root = repository(root)?;
    let head = git_text(&root, &["rev-parse", "HEAD"])?;
    ensure!(valid_sha(&head, 40), "Invalid committed source identity");
    unchanged(&root, &head)?;
    let tree = git_text(&root, &["rev-parse", &format!("{head}^{{tree}}")])?;
    ensure!(valid_sha(&tree, 40), "Invalid source tree identity");
    let epoch = git_text(&root, &["show", "-s", "--format=%ct", &head])?.parse::<u64>()?;
    ensure!(epoch <= u32::MAX as u64, "Source epoch is unsupported");
    let list = git(&root, &["ls-files", "-z"], MAX_MANIFEST as usize)?;
    ensure!(
        list == git(
            &root,
            &["ls-tree", "-r", "-z", "--name-only", &head],
            MAX_MANIFEST as usize
        )?,
        "Index list differs from committed source tree"
    );
    let tracked: Vec<String> = list
        .split(|b| *b == 0)
        .filter(|x| !x.is_empty())
        .map(|x| String::from_utf8(x.to_vec()))
        .collect::<std::result::Result<_, _>>()?;
    ensure!(tracked.len() <= MAX_FILES, "Too many source files");
    let (inventory, _) = regular(&root.join("packaging/source-files.json"), MAX_MANIFEST)?;
    let allow: Vec<String> = serde_json::from_slice(&inventory)?;
    let unique: BTreeSet<_> = allow.iter().cloned().collect();
    ensure!(
        allow == unique.into_iter().collect::<Vec<_>>() && allow == tracked,
        "Source inventory must equal sorted tracked files"
    );
    let mut files = Vec::new();
    let mut total = 0;
    for name in tracked {
        ensure!(
            relative(&name)
                && !name.split('/').any(|p| matches!(
                    p,
                    "private" | "runtime" | ".git" | "node_modules" | "target"
                ))
                && !name.starts_with(".env"),
            "Unsafe source inventory path"
        );
        let path = root.join(&name);
        for parent in Path::new(&name)
            .ancestors()
            .skip(1)
            .filter(|p| !p.as_os_str().is_empty())
        {
            ensure!(
                !fs::symlink_metadata(root.join(parent))?
                    .file_type()
                    .is_symlink(),
                "Symlink source parent refused"
            );
        }
        let (bytes, meta) = regular(&path, MAX_FILE)?;
        total += bytes.len() as u64;
        ensure!(total <= MAX_TOTAL, "Source byte budget exceeded");
        ensure!(
            !bytes
                .split(|b| *b == b'\n')
                .any(|line| line.starts_with(b"-----BEGIN ")
                    && line.windows(12).any(|x| x == b"PRIVATE KEY-")),
            "Private key material in source"
        );
        let object = format!("{head}:{name}");
        ensure!(
            git(&root, &["show", &object], MAX_FILE as usize)? == bytes,
            "Source file differs from committed bytes"
        );
        let mode_line = git_text(&root, &["ls-tree", &head, "--", &name])?;
        let mode = if mode_line.starts_with("100755 blob ") {
            0o755
        } else if mode_line.starts_with("100644 blob ") {
            0o644
        } else {
            bail!("Only committed regular source files are supported")
        };
        ensure!(
            (meta.mode() & 0o111 != 0) == (mode == 0o755),
            "Source executable mode differs from Git"
        );
        files.push((name, mode, bytes));
    }
    let version_bytes = &files
        .iter()
        .find(|x| x.0 == product::VERSION_FILE)
        .context("Version source missing")?
        .2;
    let version_text = std::str::from_utf8(version_bytes)?;
    let pattern = Regex::new(product::VERSION_PATTERN)?;
    let version = pattern
        .captures(version_text)
        .and_then(|c| c.get(1))
        .context("Version declaration missing")?
        .as_str()
        .to_owned();
    ensure!(
        Regex::new(r"^5\.0\.(0|[1-9][0-9]*)$")?.is_match(&version),
        "Only existing5.0.x source versions are supported"
    );
    unchanged(&root, &head)?;
    Ok(Source {
        root,
        head,
        tree,
        epoch,
        version,
        files,
    })
}
fn archive(source: &Source) -> Result<Vec<u8>> {
    let prefix = format!("{}_{}_source", product::ARCHIVE_PREFIX, source.version);
    let gzip = GzBuilder::new()
        .mtime(source.epoch as u32)
        .operating_system(255)
        .write(Vec::new(), Compression::new(6));
    let mut tar = Builder::new(gzip);
    for (name, mode, bytes) in &source.files {
        let mut h = Header::new_ustar();
        h.set_path(format!("{prefix}/{name}"))?;
        h.set_size(bytes.len() as u64);
        h.set_mode(*mode);
        h.set_uid(0);
        h.set_gid(0);
        h.set_mtime(source.epoch);
        h.set_username("root")?;
        h.set_groupname("root")?;
        h.set_entry_type(tar::EntryType::Regular);
        h.set_cksum();
        tar.append(&h, bytes.as_slice())?;
    }
    let bytes = tar.into_inner()?.finish()?;
    ensure!(bytes.len() as u64 <= MAX_TOTAL, "Archive budget exceeded");
    Ok(bytes)
}
fn public_key(path: &Path, root: &Path, candidate: Option<&Path>) -> Result<(Vec<u8>, Vec<u8>)> {
    let absolute = fs::canonicalize(path)?;
    ensure!(
        path.is_absolute() && absolute == path,
        "Trust key path must be absolute and canonical without symlink aliases"
    );
    let key_meta = fs::symlink_metadata(path)?;
    let parent = fs::metadata(absolute.parent().context("Trust parent missing")?)?;
    let caller = unsafe { libc::geteuid() };
    ensure!(
        (key_meta.uid() == caller || key_meta.uid() == 0)
            && key_meta.mode() & 0o022 == 0
            && (parent.uid() == caller || parent.uid() == 0)
            && parent.mode() & 0o022 == 0,
        "Independent trust must be caller/root controlled and not shared writable"
    );
    ensure!(
        !absolute.starts_with(root) && candidate.is_none_or(|c| !absolute.starts_with(c)),
        "Trust must come from outside source/candidate, not a bundled key"
    );
    let (bytes, opened_meta) = regular(path, 1024)?;
    ensure!(
        same_file(&key_meta, &opened_meta),
        "Trust identity changed before bounded read"
    );
    let mut c = Command::new("/usr/bin/openssl");
    c.args(["pkey", "-pubin", "-in", "/dev/stdin", "-outform", "DER"]);
    let der = engine(c, Some(&bytes), 128)?;
    ensure!(
        der.len() == 44 && der.starts_with(DER_PREFIX),
        "Only Ed25519 trust keys are supported"
    );
    Ok((bytes, der))
}
fn prepare_manifest(source: &Source, key: &[u8], data: &[u8]) -> Manifest {
    Manifest {
        schema: "kagnode-source-candidate-v1".into(),
        repository: product::REPOSITORY.into(),
        source_repository: product::SOURCE_REPOSITORY.into(),
        product_version: source.version.clone(),
        source_commit: source.head.clone(),
        source_tree: source.tree.clone(),
        epoch: source.epoch,
        channel: "candidate".into(),
        payload_kind: "source-data".into(),
        qualification: "unqualified; no native installation or publication".into(),
        trusted_public_key_sha256: hash(key),
        assets: vec![Asset {
            name: format!(
                "{}_{}_source.tar.gz",
                product::ARCHIVE_PREFIX,
                source.version
            ),
            bytes: data.len() as u64,
            sha256: hash(data),
        }],
    }
}
fn manifest_bytes(m: &Manifest) -> Result<Vec<u8>> {
    let mut b = serde_json::to_vec_pretty(m)?;
    b.push(b'\n');
    Ok(b)
}
fn entries(folder: &Path) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for e in fs::read_dir(folder)? {
        let e = e?;
        ensure!(names.len() < 5, "Candidate file count exceeds bound");
        ensure!(
            e.file_type()?.is_file(),
            "Candidate directories/links/special files refused"
        );
        ensure!(
            names.insert(
                e.file_name()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("Invalid candidate name"))?
            ),
            "Duplicate candidate name"
        );
    }
    Ok(names)
}
fn candidate(folder: &Path, root: &Path, key: &[u8], signed: bool) -> Result<Candidate> {
    let (raw, _) = regular(&folder.join(MANIFEST), MAX_MANIFEST)?;
    let m: Manifest = serde_json::from_slice(&raw)?;
    ensure!(
        m.schema == "kagnode-source-candidate-v1"
            && m.repository == product::REPOSITORY
            && m.source_repository == product::SOURCE_REPOSITORY
            && m.channel == "candidate"
            && m.payload_kind == "source-data"
            && m.qualification == "unqualified; no native installation or publication",
        "Unsupported candidate/legacy package format"
    );
    ensure!(
        m.assets.len() == 1
            && valid_sha(&m.source_commit, 40)
            && valid_sha(&m.source_tree, 40)
            && valid_sha(&m.trusted_public_key_sha256, 64)
            && m.trusted_public_key_sha256 == hash(key),
        "Candidate identity/trust mismatch"
    );
    let a = &m.assets[0];
    ensure!(
        relative(&a.name)
            && !a.name.contains('/')
            && a.bytes <= MAX_TOTAL
            && valid_sha(&a.sha256, 64),
        "Invalid bounded archive declaration"
    );
    let mut expected = BTreeSet::from([MANIFEST.to_owned(), SUMS.to_owned(), a.name.clone()]);
    if signed {
        expected.extend([SIGNATURE.to_owned(), PUBLIC.to_owned()]);
    }
    ensure!(
        entries(folder)? == expected,
        "Unexpected/missing candidate files"
    );
    let mut authenticated_files = std::collections::BTreeMap::new();
    if signed {
        let (sig, _) = regular(&folder.join(SIGNATURE), 64)?;
        ensure!(sig.len() == 64, "Invalid detached signature size");
        let (pub_bytes, _) = regular(&folder.join(PUBLIC), 1024)?;
        authenticated_files.insert(SIGNATURE.to_owned(), sig.clone());
        authenticated_files.insert(PUBLIC.to_owned(), pub_bytes.clone());
        let mut c = Command::new("/usr/bin/openssl");
        c.args(["pkey", "-pubin", "-in", "/dev/stdin", "-outform", "DER"]);
        ensure!(
            engine(c, Some(&pub_bytes), 128)? == key,
            "Bundled public key does not match independent trust"
        );
        // Freeze only public inputs in an external private temp directory. Signature
        // verification is before archive parsing or committed-source reconstruction.
        let temp = tempfile::tempdir()?;
        fs::write(temp.path().join("m"), &raw)?;
        fs::write(temp.path().join("s"), sig)?;
        fs::write(temp.path().join("p"), pub_bytes)?;
        let mut c = Command::new("/usr/bin/openssl");
        c.args(["pkeyutl", "-verify", "-rawin", "-pubin", "-inkey"])
            .arg(temp.path().join("p"))
            .arg("-in")
            .arg(temp.path().join("m"))
            .arg("-sigfile")
            .arg(temp.path().join("s"));
        engine(c, None, 4096)?;
    }
    ensure!(
        raw == manifest_bytes(&m)?,
        "Manifest must use canonical candidate encoding"
    );
    let source = snapshot(root)?;
    let expected_archive = archive(&source)?;
    let expected_manifest = prepare_manifest(&source, key, &expected_archive);
    ensure!(
        raw == manifest_bytes(&expected_manifest)?,
        "Candidate does not match current committed source/version/tree"
    );
    let (data, _) = regular(&folder.join(&a.name), MAX_TOTAL)?;
    ensure!(
        data.len() as u64 == a.bytes && hash(&data) == a.sha256 && data == expected_archive,
        "Archive differs from canonical committed source; never extracted"
    );
    let mut frozen = std::collections::BTreeMap::from([
        (MANIFEST.to_owned(), raw.clone()),
        (a.name.clone(), data.clone()),
    ]);
    frozen.extend(authenticated_files);
    let (sums, _) = regular(&folder.join(SUMS), MAX_MANIFEST)?;
    let expected_sums: String = frozen
        .iter()
        .map(|(name, bytes)| format!("{}  {}\n", hash(bytes), name))
        .collect();
    ensure!(
        sums == expected_sums.as_bytes(),
        "Candidate changed while checksums were verified"
    );
    check_sums(folder)?;
    for (name, bytes) in &frozen {
        ensure!(
            regular(&folder.join(name), MAX_TOTAL)?.0 == *bytes,
            "Candidate changed before verification completed"
        );
    }
    ensure!(
        regular(&folder.join(SUMS), MAX_MANIFEST)?.0 == sums,
        "Candidate checksums changed"
    );
    unchanged(&source.root, &source.head)?;
    Ok(Candidate {
        manifest: m,
        raw,
        archive: data,
    })
}
fn new_output(
    path: &Path,
    root: &Path,
    input: Option<&Path>,
    trust: &Path,
    secret: Option<&Path>,
) -> Result<PathBuf> {
    let parent = directory(path.parent().context("Output parent missing")?)?;
    let name = path.file_name().context("Output basename missing")?;
    ensure!(
        Path::new(name)
            .components()
            .all(|x| matches!(x, Component::Normal(_))),
        "Invalid output basename"
    );
    let out = parent.join(name);
    ensure!(
        !out.starts_with(root)
            && input.is_none_or(|i| !out.starts_with(i) && !i.starts_with(&out))
            && !fs::canonicalize(trust)?.starts_with(&out)
            && secret.is_none_or(|s| fs::canonicalize(s).is_ok_and(|s| !s.starts_with(&out))),
        "Source/output/input/key separation required"
    );
    let meta = fs::metadata(&parent)?;
    ensure!(
        meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o022 == 0,
        "Output parent must be owner-controlled"
    );
    fs::create_dir(&out)?;
    fs::set_permissions(&out, fs::Permissions::from_mode(0o700))?;
    Ok(out)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
fn write_sums(folder: &Path) -> Result<()> {
    let names = entries(folder)?;
    let mut sums = String::new();
    for name in names {
        if name != SUMS {
            let (data, _) = regular(&folder.join(&name), MAX_TOTAL)?;
            sums.push_str(&format!("{}  {}\n", hash(&data), name));
        }
    }
    write_new(&folder.join(SUMS), sums.as_bytes())
}
fn check_sums(folder: &Path) -> Result<()> {
    let (actual, _) = regular(&folder.join(SUMS), MAX_MANIFEST)?;
    let mut expected = String::new();
    for name in entries(folder)? {
        if name != SUMS {
            let (data, _) = regular(&folder.join(&name), MAX_TOTAL)?;
            expected.push_str(&format!("{}  {}\n", hash(&data), name));
        }
    }
    ensure!(actual == expected.as_bytes(), "Candidate checksums differ");
    Ok(())
}
pub fn prepare(root: &Path, out: &Path, trust: &Path) -> Result<Manifest> {
    prepare_inner(root, out, trust, || {})
}
fn prepare_inner(
    root: &Path,
    out: &Path,
    trust: &Path,
    after_archive: impl FnOnce(),
) -> Result<Manifest> {
    let source = snapshot(root)?;
    let (_, der) = public_key(trust, &source.root, None)?;
    let data = archive(&source)?;
    let m = prepare_manifest(&source, &der, &data);
    after_archive();
    unchanged(&source.root, &source.head)?;
    let out = new_output(out, &source.root, None, trust, None)?;
    write_new(&out.join(&m.assets[0].name), &data)?;
    write_new(&out.join(MANIFEST), &manifest_bytes(&m)?)?;
    write_sums(&out)?;
    unchanged(&source.root, &source.head)?;
    candidate(&out, &source.root, &der, false)?;
    Ok(m)
}
pub fn sign(
    root: &Path,
    input: &Path,
    out: &Path,
    trust: &Path,
    secret: &Path,
) -> Result<Manifest> {
    let root = repository(root)?;
    let input = directory(input)?;
    let (pub_bytes, der) = public_key(trust, &root, Some(&input))?;
    let candidate = candidate(&input, &root, &der, false)?;
    let secret_path = fs::canonicalize(secret)?;
    ensure!(
        secret.is_absolute() && secret_path == secret,
        "Signing identity path must be absolute and canonical"
    );
    let secret_meta = fs::symlink_metadata(secret)?;
    let secret_parent = fs::metadata(secret_path.parent().context("Identity parent missing")?)?;
    ensure!(
        secret_meta.uid() == unsafe { libc::geteuid() }
            && secret_meta.mode() & 0o077 == 0
            && (secret_parent.uid() == unsafe { libc::geteuid() } || secret_parent.uid() == 0)
            && secret_parent.mode() & 0o022 == 0,
        "Signing identity must remain privately caller-controlled"
    );
    ensure!(
        !secret_path.starts_with(&root) && !secret_path.starts_with(&input),
        "Signing identity must remain external"
    );
    let (private, meta) = regular(secret, 1024)?;
    let private = Zeroizing::new(private);
    ensure!(
        same_file(&secret_meta, &meta),
        "Signing identity changed before bounded read"
    );
    ensure!(
        meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
        "Signing identity must be private and owned by caller"
    );
    let mut c = Command::new("/usr/bin/openssl");
    c.args([
        "pkey",
        "-in",
        "/dev/stdin",
        "-passin",
        "pass:",
        "-pubout",
        "-outform",
        "DER",
    ]);
    ensure!(
        engine(c, Some(&private), 128)? == der,
        "Signing identity does not match independent trust"
    );
    let out = new_output(out, &root, Some(&input), trust, Some(secret))?;
    write_new(&out.join(MANIFEST), &candidate.raw)?;
    write_new(
        &out.join(&candidate.manifest.assets[0].name),
        &candidate.archive,
    )?;
    write_new(&out.join(PUBLIC), &pub_bytes)?;
    let mut c = Command::new("/usr/bin/openssl");
    c.args([
        "pkeyutl",
        "-sign",
        "-rawin",
        "-inkey",
        "/dev/stdin",
        "-passin",
        "pass:",
        "-in",
    ])
    .arg(out.join(MANIFEST));
    let sig = engine(c, Some(&private), 64)?;
    ensure!(sig.len() == 64, "Invalid engine signature output");
    write_new(&out.join(SIGNATURE), &sig)?;
    write_sums(&out)?;
    self::candidate(&out, &root, &der, true)?;
    Ok(candidate.manifest)
}
pub fn verify(root: &Path, input: &Path, trust: &Path) -> Result<Manifest> {
    let root = repository(root)?;
    let input = directory(input)?;
    let (_, der) = public_key(trust, &root, Some(&input))?;
    Ok(candidate(&input, &root, &der, true)?.manifest)
}
pub fn check_source(root: &Path) -> Result<(String, usize)> {
    let source = snapshot(root)?;
    Ok((source.head, source.files.len()))
}

pub fn run(args: Vec<String>) -> Result<Manifest> {
    let p = |i: usize| Path::new(&args[i]);
    match args.first().map(String::as_str) {
        Some("prepare") if args.len() == 4 => prepare(p(1), p(2), p(3)),
        Some("sign") if args.len() == 6 => sign(p(1), p(2), p(3), p(4), p(5)),
        Some("verify") if args.len() == 4 => verify(p(1), p(2), p(3)),
        _ => bail!(
            "Usage: inventory ROOT | prepare ROOT OUTPUT EXTERNAL_PUBLIC_KEY | sign ROOT INPUT OUTPUT EXTERNAL_PUBLIC_KEY EXTERNAL_PRIVATE_KEY | verify ROOT INPUT EXTERNAL_PUBLIC_KEY; source-data candidates only, never publishes or installs"
        ),
    }
}

#[cfg(test)]
mod tests;
