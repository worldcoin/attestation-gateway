use std::process::Command;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

fn get_git_rev() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;

    if output.status.success() {
        String::from_utf8(output.stdout).ok()
    } else {
        None
    }
}

fn get_compile_date() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("UTC build date can be formatted as RFC 3339")
}

fn main() {
    println!("cargo:rustc-env=STATIC_BUILD_DATE={}", get_compile_date());

    if let Some(rev) = get_git_rev() {
        println!("cargo:rustc-env=GIT_REV={rev}");
    }
}
