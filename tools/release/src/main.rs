// SPDX-License-Identifier: AGPL-3.0-only
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if matches!(args.first().map(String::as_str), Some("--help" | "-h")) && args.len() == 1 {
        println!(
            "Source-data candidate tooling; never publishes or installs.\ninventory ROOT\nprepare ROOT OUTPUT EXTERNAL_PUBLIC_KEY\nsign ROOT INPUT OUTPUT EXTERNAL_PUBLIC_KEY EXTERNAL_PRIVATE_KEY\nverify ROOT INPUT EXTERNAL_PUBLIC_KEY"
        );
        return;
    }
    if args.first().map(String::as_str) == Some("inventory") && args.len() == 2 {
        match kagnode_passwords_release_candidate::check_source(std::path::Path::new(&args[1])) {
            Ok((head, count)) => println!(
                "{}",
                serde_json::json!({"status":"committed source inventory checked","source_commit":head,"tracked_files":count,"signature_verified":false,"publication":false})
            ),
            Err(error) => {
                eprintln!("Source inventory refused: {error:#}");
                std::process::exit(1);
            }
        }
        return;
    }
    let signature_verified = matches!(args.first().map(String::as_str), Some("sign" | "verify"));
    match kagnode_passwords_release_candidate::run(args) {
        Ok(manifest) => println!(
            "{}",
            serde_json::json!({"status":"source-data candidate checked", "source_commit":manifest.source_commit,"signature_verified":signature_verified,"publication":false,"native_qualification":false})
        ),
        Err(error) => {
            eprintln!("Source candidate refused: {error:#}");
            std::process::exit(1);
        }
    }
}
