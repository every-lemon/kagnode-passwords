// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use std::os::unix::fs::symlink;
struct Fixture {
    temp: tempfile::TempDir,
    root: PathBuf,
    trust: PathBuf,
    secret: PathBuf,
}
fn command(mut c: Command) -> Vec<u8> {
    c.stderr(Stdio::null());
    let o = c.output().unwrap();
    assert!(o.status.success());
    o.stdout
}
fn cmd(root: &Path, args: &[&str]) -> Vec<u8> {
    let mut c = Command::new("/usr/bin/git");
    clean_env(&mut c);
    c.args(["-c", "core.hooksPath=/dev/null", "-C"])
        .arg(root)
        .args(args);
    command(c)
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("repo");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("packaging")).unwrap();
        let version = root.join(product::VERSION_FILE);
        fs::create_dir_all(version.parent().unwrap()).unwrap();
        fs::write(
            version,
            if product::VERSION_FILE == "Cargo.toml" {
                b"[package]\nname = \"fixture\"\nversion = \"5.0.3\"\n".as_slice()
            } else {
                b"#!/bin/sh\nversion=5.0.3\n".as_slice()
            },
        )
        .unwrap();
        fs::write(root.join("README.md"), b"Synthetic public source\n").unwrap();
        fs::write(root.join(".gitignore"), b"/private/\n").unwrap();
        fs::write(root.join("packaging/source-files.json"), b"[]\n").unwrap();
        cmd(&root, &["init", "--quiet"]);
        cmd(&root, &["config", "user.name", "Fixture"]);
        cmd(&root, &["config", "user.email", "fixture@example.invalid"]);
        let secret = temp.path().join("external.pem");
        let trust = temp.path().join("external-public.pem");
        let mut c = Command::new("/usr/bin/openssl");
        c.args(["genpkey", "-algorithm", "ED25519", "-out"])
            .arg(&secret);
        command(c);
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
        let mut c = Command::new("/usr/bin/openssl");
        c.args(["pkey", "-in"])
            .arg(&secret)
            .arg("-pubout")
            .arg("-out")
            .arg(&trust);
        command(c);
        let f = Self {
            temp,
            root,
            trust,
            secret,
        };
        f.commit();
        f
    }
    fn out(&self, name: &str) -> PathBuf {
        self.temp.path().join(name)
    }
    fn commit(&self) {
        cmd(&self.root, &["add", "--all"]);
        let names = cmd(&self.root, &["ls-files", "-z"]);
        let list: Vec<String> = names
            .split(|b| *b == 0)
            .filter(|b| !b.is_empty())
            .map(|b| String::from_utf8(b.to_vec()).unwrap())
            .collect();
        fs::write(
            self.root.join("packaging/source-files.json"),
            serde_json::to_vec_pretty(&list).unwrap(),
        )
        .unwrap();
        cmd(&self.root, &["add", "--all"]);
        cmd(
            &self.root,
            &[
                "commit",
                "--quiet",
                "--allow-empty",
                "-m",
                "Synthetic fixture",
            ],
        );
    }
    fn prepare(&self, name: &str) -> PathBuf {
        let p = self.out(name);
        prepare(&self.root, &p, &self.trust).unwrap();
        p
    }
    fn signed(&self) -> PathBuf {
        let p = self.prepare("unsigned");
        let s = self.out("signed");
        sign(&self.root, &p, &s, &self.trust, &self.secret).unwrap();
        s
    }
    fn rewrite_sums(&self, p: &Path) {
        fs::remove_file(p.join(SUMS)).unwrap();
        write_sums(p).unwrap();
    }
    fn resign(&self, p: &Path) {
        let mut c = Command::new("/usr/bin/openssl");
        c.args(["pkeyutl", "-sign", "-rawin", "-inkey"])
            .arg(&self.secret)
            .arg("-in")
            .arg(p.join(MANIFEST))
            .arg("-out")
            .arg(p.join(SIGNATURE));
        command(c);
        self.rewrite_sums(p);
    }
}
#[test]
fn source_and_signed_candidates_repeat_byte_for_byte() {
    let f = Fixture::new();
    let a = f.prepare("a");
    let b = f.prepare("b");
    for n in entries(&a).unwrap() {
        assert_eq!(fs::read(a.join(&n)).unwrap(), fs::read(b.join(n)).unwrap());
    }
    let x = f.out("x");
    let y = f.out("y");
    sign(&f.root, &a, &x, &f.trust, &f.secret).unwrap();
    sign(&f.root, &b, &y, &f.trust, &f.secret).unwrap();
    for n in entries(&x).unwrap() {
        assert_eq!(fs::read(x.join(&n)).unwrap(), fs::read(y.join(n)).unwrap());
    }
    let m = verify(&f.root, &x, &f.trust).unwrap();
    assert_eq!(m.channel, "candidate");
    assert_eq!(m.payload_kind, "source-data");
    assert_eq!(m.assets.len(), 1);
    assert!(m.qualification.starts_with("unqualified"));
}
#[test]
fn signature_is_checked_before_changed_archive() {
    let f = Fixture::new();
    let p = f.signed();
    fs::write(p.join(SIGNATURE), [0u8; 64]).unwrap();
    let m: Manifest = serde_json::from_slice(&fs::read(p.join(MANIFEST)).unwrap()).unwrap();
    fs::write(p.join(&m.assets[0].name), b"not even a gzip stream").unwrap();
    let e = verify(&f.root, &p, &f.trust).unwrap_err().to_string();
    assert_eq!(e, "Fixed engine refused input");
}
#[test]
fn independent_trust_is_required_not_bundled_key() {
    let f = Fixture::new();
    let p = f.signed();
    assert!(verify(&f.root, &p, &p.join(PUBLIC)).is_err());
    let g = Fixture::new();
    assert!(verify(&f.root, &p, &g.trust).is_err());
    assert!(run(vec!["verify".into()]).is_err());
}
#[test]
fn missing_signature_and_unknown_files_fail_closed() {
    let f = Fixture::new();
    let p = f.signed();
    fs::rename(p.join(SIGNATURE), p.join("extra")).unwrap();
    assert!(verify(&f.root, &p, &f.trust).is_err());
    fs::rename(p.join("extra"), p.join(SIGNATURE)).unwrap();
    fs::write(p.join("unexpected"), b"x").unwrap();
    assert!(verify(&f.root, &p, &f.trust).is_err());
}
#[test]
fn source_output_input_and_keys_must_be_separate() {
    let f = Fixture::new();
    assert!(prepare(&f.root, &f.root.join("out"), &f.trust).is_err());
    let a = f.prepare("a");
    assert!(sign(&f.root, &a, &a.join("out"), &f.trust, &f.secret).is_err());
    let secret = f.root.join("private/key.pem");
    fs::create_dir_all(secret.parent().unwrap()).unwrap();
    fs::copy(&f.secret, &secret).unwrap();
    assert!(sign(&f.root, &a, &f.out("bad"), &f.trust, &secret).is_err());
}
#[test]
fn existing_output_is_never_overwritten() {
    let f = Fixture::new();
    let out = f.out("existing");
    fs::create_dir(&out).unwrap();
    fs::write(out.join("marker"), b"retain").unwrap();
    assert!(prepare(&f.root, &out, &f.trust).is_err());
    assert_eq!(fs::read(out.join("marker")).unwrap(), b"retain");
}
#[test]
fn dirty_tracked_and_untracked_inputs_are_rejected() {
    let f = Fixture::new();
    fs::write(f.root.join("README.md"), b"changed").unwrap();
    assert!(prepare(&f.root, &f.out("bad"), &f.trust).is_err());
    cmd(&f.root, &["checkout", "--", "README.md"]);
    fs::write(f.root.join("untracked"), b"private").unwrap();
    assert!(prepare(&f.root, &f.out("bad2"), &f.trust).is_err());
}
#[test]
fn inventory_must_be_sorted_complete_unique() {
    for variant in 0..3 {
        let f = Fixture::new();
        let p = f.root.join("packaging/source-files.json");
        let mut list: Vec<String> = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
        match variant {
            0 => {
                list.pop();
            }
            1 => list.push(list[0].clone()),
            _ => list.reverse(),
        };
        fs::write(p, serde_json::to_vec(&list).unwrap()).unwrap();
        cmd(&f.root, &["add", "--all"]);
        cmd(
            &f.root,
            &["commit", "--quiet", "-m", "Invalid inventory fixture"],
        );
        assert!(prepare(&f.root, &f.out("bad"), &f.trust).is_err());
    }
}
#[test]
fn tracked_symlinks_and_hardlinks_are_refused() {
    let f = Fixture::new();
    symlink(&f.trust, f.root.join("link")).unwrap();
    f.commit();
    assert!(prepare(&f.root, &f.out("bad"), &f.trust).is_err());
    let f = Fixture::new();
    fs::hard_link(f.root.join("README.md"), f.out("hardlink")).unwrap();
    assert!(prepare(&f.root, &f.out("bad"), &f.trust).is_err());
}
#[test]
fn symlink_candidate_trust_or_output_parent_is_refused() {
    let f = Fixture::new();
    let p = f.signed();
    let link = f.out("link");
    symlink(&p, &link).unwrap();
    assert!(verify(&f.root, &link, &f.trust).is_err());
    let keylink = f.out("key-link");
    symlink(&f.trust, &keylink).unwrap();
    assert!(verify(&f.root, &p, &keylink).is_err());
    let parent = f.out("parent-link");
    symlink(f.temp.path(), &parent).unwrap();
    assert!(prepare(&f.root, &parent.join("bad"), &f.trust).is_err());
}
#[test]
fn source_private_key_material_is_refused() {
    let f = Fixture::new();
    let key = f.root.join("public-file");
    let header = ["-----BEGIN ", "PRIVATE KEY-----\nfixture\n"].concat();
    fs::write(key, header).unwrap();
    f.commit();
    assert!(prepare(&f.root, &f.out("bad"), &f.trust).is_err());
}
#[test]
fn signing_key_permissions_and_identity_are_enforced() {
    let f = Fixture::new();
    let a = f.prepare("a");
    fs::set_permissions(&f.secret, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(sign(&f.root, &a, &f.out("bad"), &f.trust, &f.secret).is_err());
    fs::set_permissions(&f.secret, fs::Permissions::from_mode(0o600)).unwrap();
    let g = Fixture::new();
    assert!(sign(&f.root, &a, &f.out("bad2"), &f.trust, &g.secret).is_err());
}
#[test]
fn changed_head_cannot_reuse_an_old_candidate() {
    let f = Fixture::new();
    let p = f.signed();
    fs::write(f.root.join("README.md"), b"Next committed source\n").unwrap();
    f.commit();
    assert!(verify(&f.root, &p, &f.trust).is_err());
}
#[test]
fn deterministic_mid_build_source_mutation_is_rejected() {
    let f = Fixture::new();
    let out = f.out("bad");
    let result = prepare_inner(&f.root, &out, &f.trust, || {
        fs::write(f.root.join("README.md"), b"raced\n").unwrap()
    });
    assert!(result.is_err());
    assert!(!out.exists());
}
#[test]
fn manifest_unknown_and_duplicate_fields_are_rejected() {
    let f = Fixture::new();
    let p = f.signed();
    let original = fs::read_to_string(p.join(MANIFEST)).unwrap();
    for raw in [
        original.replacen('{', "{\"unknown\":true,", 1),
        original.replacen('{', "{\"schema\":\"duplicate\",", 1),
    ] {
        fs::write(p.join(MANIFEST), raw).unwrap();
        f.resign(&p);
        assert!(verify(&f.root, &p, &f.trust).is_err());
    }
}
#[test]
fn legacy_unsigned_packages_are_not_silently_signed() {
    let f = Fixture::new();
    let a = f.prepare("a");
    fs::write(
        a.join(MANIFEST),
        br#"{"schema":1,"repository":"every-lemon/legacy","channel":"stable","assets":{}}"#,
    )
    .unwrap();
    assert!(sign(&f.root, &a, &f.out("bad"), &f.trust, &f.secret).is_err());
}
#[test]
fn malicious_signed_archive_is_never_extracted() {
    for kind in ["../escape", "/absolute", "symlink", "duplicate"] {
        let f = Fixture::new();
        let p = f.signed();
        let mut m: Manifest = serde_json::from_slice(&fs::read(p.join(MANIFEST)).unwrap()).unwrap();
        let mut header = Header::new_ustar();
        header.set_path("fixture").unwrap();
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(1);
        header.set_size(if kind == "symlink" { 0 } else { 4 });
        let name = match kind {
            "../escape" => "../escape",
            "/absolute" => "/absolute",
            _ => "duplicate",
        };
        header.as_mut_bytes()[..100].fill(0);
        header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
        if kind == "symlink" {
            header.set_entry_type(tar::EntryType::Symlink);
            header.as_mut_bytes()[157..257].fill(0);
            header.as_mut_bytes()[157..166].copy_from_slice(b"../escape");
        }
        header.set_cksum();
        let mut raw = header.as_bytes().to_vec();
        if kind != "symlink" {
            raw.extend_from_slice(b"evil");
            raw.resize(1024, 0);
        }
        if kind == "duplicate" {
            let copy = raw.clone();
            raw.extend_from_slice(&copy);
        }
        raw.extend_from_slice(&[0; 1024]);
        let mut zip = GzBuilder::new()
            .mtime(1)
            .write(Vec::new(), Compression::new(6));
        zip.write_all(&raw).unwrap();
        let data = zip.finish().unwrap();
        fs::write(p.join(&m.assets[0].name), &data).unwrap();
        m.assets[0].bytes = data.len() as u64;
        m.assets[0].sha256 = hash(&data);
        fs::write(p.join(MANIFEST), manifest_bytes(&m).unwrap()).unwrap();
        f.resign(&p);
        assert!(verify(&f.root, &p, &f.trust).is_err());
        assert!(!f.out("escape").exists());
    }
}
#[test]
fn count_and_size_bounds_reject_before_signing() {
    let f = Fixture::new();
    let p = f.signed();
    let mut m: Manifest = serde_json::from_slice(&fs::read(p.join(MANIFEST)).unwrap()).unwrap();
    m.assets[0].bytes = MAX_TOTAL + 1;
    fs::write(p.join(MANIFEST), manifest_bytes(&m).unwrap()).unwrap();
    f.resign(&p);
    assert!(verify(&f.root, &p, &f.trust).is_err());
    m.assets[0].bytes = 1;
    m.assets.push(m.assets[0].clone());
    fs::write(p.join(MANIFEST), manifest_bytes(&m).unwrap()).unwrap();
    f.resign(&p);
    assert!(verify(&f.root, &p, &f.trust).is_err());
}
#[test]
fn executable_config_and_includes_are_refused_without_execution() {
    let f = Fixture::new();
    let include = f.out("include-config");
    fs::write(&include, b"[alias]\nx = !echo unsafe\n").unwrap();
    let config = f.root.join(".git/config");
    let mut raw = fs::read_to_string(&config).unwrap();
    raw.push_str(&format!("\n[include]\npath = {}\n", include.display()));
    fs::write(config, raw).unwrap();
    assert!(prepare(&f.root, &f.out("bad"), &f.trust).is_err());
}
#[test]
fn git_replace_does_not_change_source_identity() {
    let f = Fixture::new();
    let first = String::from_utf8(cmd(&f.root, &["rev-parse", "HEAD"]))
        .unwrap()
        .trim()
        .to_owned();
    fs::write(f.root.join("README.md"), b"Replacement body\n").unwrap();
    f.commit();
    let second = String::from_utf8(cmd(&f.root, &["rev-parse", "HEAD"]))
        .unwrap()
        .trim()
        .to_owned();
    cmd(&f.root, &["reset", "--hard", &first]);
    cmd(&f.root, &["replace", &first, &second]);
    let m = prepare(&f.root, &f.out("good"), &f.trust).unwrap();
    assert_eq!(m.source_commit, first);
}

#[test]
fn oversized_source_file_is_refused_before_read() {
    let f = Fixture::new();
    let path = f.root.join("oversize");
    std::fs::File::create(&path)
        .unwrap()
        .set_len(MAX_FILE + 1)
        .unwrap();
    f.commit();
    assert!(prepare(&f.root, &f.out("bad"), &f.trust).is_err());
}
#[test]
fn too_many_tracked_source_files_are_refused() {
    let f = Fixture::new();
    fs::create_dir(f.root.join("many")).unwrap();
    for i in 0..MAX_FILES {
        fs::write(f.root.join(format!("many/f{i:04}")), b"x").unwrap();
    }
    f.commit();
    assert!(prepare(&f.root, &f.out("bad"), &f.trust).is_err());
}

#[test]
fn independent_trust_must_not_be_shared_writable_or_aliased() {
    let f = Fixture::new();
    let p = f.signed();
    fs::set_permissions(&f.trust, fs::Permissions::from_mode(0o666)).unwrap();
    let error = verify(&f.root, &p, &f.trust).unwrap_err().to_string();
    assert!(error.contains("Independent trust"));
    fs::set_permissions(&f.trust, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(verify(&f.root, &p, &f.root.join("../external-public.pem")).is_err());
}

#[test]
fn fifo_input_is_refused_without_blocking_open() {
    use std::os::unix::ffi::OsStrExt;
    let f = Fixture::new();
    let path = f.out("fifo");
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(regular(&path, MAX_MANIFEST).is_err());
    });
    assert_eq!(rx.recv_timeout(Duration::from_secs(1)), Ok(true));
}

#[test]
fn candidate_directory_enumeration_has_a_fixed_file_bound() {
    let f = Fixture::new();
    let folder = f.out("many-candidate-files");
    fs::create_dir(&folder).unwrap();
    for i in 0..6 {
        fs::write(folder.join(format!("file-{i}")), b"x").unwrap();
    }
    assert!(
        entries(&folder)
            .unwrap_err()
            .to_string()
            .contains("file count exceeds bound")
    );
}
