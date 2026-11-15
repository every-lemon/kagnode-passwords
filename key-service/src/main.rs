use anyhow::{Result, ensure};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::{get, post},
};
use clap::Parser;
use kagnode_vault_keys::{Request, Store};
use serde_json::{Value, json};
use std::{
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
#[derive(Parser)]
#[command(
    version,
    about = "KagNode trusted vault-key service; private Unix transport only"
)]
struct Args {
    #[arg(long)]
    database: PathBuf,
    #[arg(long)]
    wrapping_key: PathBuf,
    #[arg(long)]
    authority_key: PathBuf,
    #[arg(long, default_value = "https://nebulacoder.com")]
    issuer: String,
    #[arg(long, default_value = "/run/kagnode-vault-keys/service.sock")]
    socket: PathBuf,
}
fn ancestors(path: &Path) -> Result<()> {
    let uid = unsafe { libc::geteuid() };
    for parent in path.ancestors().skip(1) {
        let meta = parent.symlink_metadata()?;
        ensure!(
            meta.is_dir()
                && !meta.file_type().is_symlink()
                && (meta.uid() == 0 || meta.uid() == uid)
                && meta.mode() & 0o022 == 0,
            "Service paths must have protected ancestors"
        );
    }
    Ok(())
}
fn secret(path: &Path) -> Result<Vec<u8>> {
    ancestors(path)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && !meta.file_type().is_symlink()
            && meta.nlink() == 1
            && (meta.uid() == 0 || meta.uid() == unsafe { libc::geteuid() })
            && meta.mode() & 0o027 == 0
            && meta.len() == 32,
        "Keys must be private regular 32-byte files"
    );
    for p in path.ancestors().skip(1) {
        let m = p.symlink_metadata()?;
        ensure!(
            m.is_dir() && !m.file_type().is_symlink() && m.mode() & 0o022 == 0,
            "Key ancestors must be protected directories"
        );
    }
    let mut key = Vec::with_capacity(32);
    file.take(33).read_to_end(&mut key)?;
    ensure!(key.len() == 32, "Private key changed while reading");
    Ok(key)
}
async fn execute(
    State(store): State<Arc<Store>>,
    Json(input): Json<Request>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"clock_unavailable"})),
            )
        })?
        .as_secs();
    let now = i64::try_from(now).map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"clock_unavailable"})),
        )
    })?;
    // SQLite work is bounded and serialized outside Tokio's network workers.
    tokio::task::spawn_blocking(move || store.execute(input, now))
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"service_unavailable"})),
            )
        })?
        .map(Json)
        .map_err(|_| {
            (
                StatusCode::FORBIDDEN,
                Json(json!({"error":"grant_or_envelope_unavailable"})),
            )
        })
}
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(
        args.database.is_absolute() && args.socket.is_absolute(),
        "Use absolute service paths"
    );
    use std::os::unix::ffi::OsStrExt;
    ensure!(
        args.socket.as_os_str().as_bytes().len() <= 107,
        "Use a short Unix socket path (at most 107 bytes)"
    );
    ancestors(&args.database)?;
    ancestors(&args.socket)?;
    let uid = unsafe { libc::geteuid() };
    let socket_parent = args.socket.parent().unwrap().symlink_metadata()?;
    ensure!(
        socket_parent.uid() == uid,
        "Socket directory must belong to the service identity"
    );
    let parent = args.database.parent().unwrap();
    let m = parent.symlink_metadata()?;
    ensure!(
        m.is_dir() && !m.file_type().is_symlink() && m.uid() == uid && m.mode() & 0o077 == 0,
        "Database directory must be private"
    );
    if args.database.exists() {
        let m = args.database.symlink_metadata()?;
        ensure!(
            m.is_file() && !m.file_type().is_symlink() && m.nlink() == 1 && m.mode() & 0o077 == 0,
            "Database must be private"
        );
    }
    ensure!(
        !args.socket.exists() && !args.socket.is_symlink(),
        "Inspect the existing service socket before startup"
    );
    let store = Arc::new(Store::open(
        &args.database,
        secret(&args.wrapping_key)?,
        secret(&args.authority_key)?,
        args.issuer,
    )?);
    std::fs::set_permissions(&args.database, std::fs::Permissions::from_mode(0o600))?;
    let listener = tokio::net::UnixListener::bind(&args.socket)?;
    std::fs::set_permissions(&args.socket, std::fs::Permissions::from_mode(0o660))?;
    let app = Router::new()
        .route(
            "/healthz",
            get(|| async {
                Json(json!({"version":env!("CARGO_PKG_VERSION"),"service":"kagnode-vault-keys"}))
            }),
        )
        .route("/api/v1/execute", post(execute))
        .layer(DefaultBodyLimit::max(4096))
        .with_state(store);
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    std::fs::remove_file(args.socket)?;
    Ok(())
}
