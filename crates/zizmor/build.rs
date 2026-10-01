#![allow(clippy::unwrap_used)]

use fst::{MapBuilder, SetBuilder};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, io};

fn do_context_capabilities() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let source = Path::new(&manifest_dir).join("data/context-capabilities.csv");

    println!(
        "cargo::rerun-if-changed={source}",
        source = source.display()
    );

    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir).join("context-capabilities.fst");

    let out = io::BufWriter::new(File::create(out_path).unwrap());
    let mut build = MapBuilder::new(out).unwrap();

    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_path(source)
        .unwrap();

    for record in rdr.records() {
        let record = record.unwrap();
        let context = record.get(0).unwrap();
        let capability = match record.get(1).unwrap() {
            "arbitrary" => 0,
            "structured" => 1,
            "fixed" => 2,
            _ => panic!("Unknown capability"),
        };

        build.insert(context, capability).unwrap();
    }

    build.finish().unwrap();
}

fn do_codeql_injection_sinks() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let source = Path::new(&manifest_dir).join("data/codeql-injection-sinks.json");
    let target = Path::new(&env::var("OUT_DIR").unwrap()).join("codeql-injection-sinks.json");

    println!(
        "cargo::rerun-if-changed={source}",
        source = source.display()
    );

    fs::copy(source, target).unwrap();
}

/// Helper to dedup building FST files from static lists without any specific processing
/// before inserting
fn do_fst_for_static_list(name: &str) {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let source = Path::new(&manifest_dir).join(format!("data/{name}.txt"));
    let target = Path::new(&env::var("OUT_DIR").unwrap()).join(format!("{name}.fst"));

    println!(
        "cargo::rerun-if-changed={source}",
        source = source.display()
    );

    let out = io::BufWriter::new(File::create(target).unwrap());
    let mut build = SetBuilder::new(out).unwrap();

    let contents = fs::read_to_string(source).unwrap();
    for line in contents.lines() {
        build.insert(line).unwrap();
    }

    build.finish().unwrap();
}

fn main() {
    do_context_capabilities();
    do_codeql_injection_sinks();
    do_fst_for_static_list("archived-repos");
    do_fst_for_static_list("github-hosted-runners");

    let workspace_root = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("..")
        .join("..");
    commit_info(&workspace_root);

    println!(
        "cargo::rustc-env=RUST_HOST_TARGET={}",
        env::var("TARGET").unwrap()
    );
}

fn commit_info(workspace_root: &Path) {
    let git_dir = workspace_root.join(".git");
    if !git_dir.exists() {
        return;
    }

    if let Some(git_head_path) = git_head(&git_dir) {
        println!("cargo:rerun-if-changed={}", git_head_path.display());

        if let Ok(git_head_contents) = fs::read_to_string(&git_head_path) {
            let mut git_ref_parts = git_head_contents.split_whitespace();
            git_ref_parts.next();
            if let Some(git_ref) = git_ref_parts.next() {
                watch_git_ref(&git_head_path, git_ref);
            }
        }
    }

    let Ok(output) = Command::new("git")
        .args([
            "log",
            "-1",
            "--date=short",
            "--abbrev=9",
            "--format=%H %h %cd %(describe:tags)",
        ])
        .current_dir(workspace_root)
        .output()
    else {
        return;
    };
    if !output.status.success() {
        return;
    }

    let stdout = String::from_utf8(output.stdout).unwrap();
    let mut parts = stdout.split_whitespace();
    let Some(commit_hash) = parts.next() else {
        return;
    };
    let Some(short_commit_hash) = parts.next() else {
        return;
    };
    let Some(commit_date) = parts.next() else {
        return;
    };
    println!("cargo::rustc-env=ZIZMOR_COMMIT_HASH={commit_hash}");
    println!("cargo::rustc-env=ZIZMOR_COMMIT_SHORT_HASH={short_commit_hash}");
    println!("cargo::rustc-env=ZIZMOR_COMMIT_DATE={commit_date}");

    if let Some(describe) = parts.next() {
        let mut describe_parts = describe.rsplitn(3, '-');
        describe_parts.next();
        if let Some(distance) = describe_parts.next() {
            println!("cargo::rustc-env=ZIZMOR_LAST_TAG_DISTANCE={distance}");
        }
    }
}

fn git_head(git_dir: &Path) -> Option<PathBuf> {
    if git_dir.is_dir() {
        return Some(git_dir.join("HEAD"));
    }
    if !git_dir.is_file() {
        return None;
    }

    println!("cargo:rerun-if-changed={}", git_dir.display());
    let contents = fs::read_to_string(git_dir).ok()?;
    let (label, worktree_path) = contents.split_once(':')?;
    if label != "gitdir" {
        return None;
    }
    let worktree_path = PathBuf::from(worktree_path.trim());
    let worktree_path = if worktree_path.is_absolute() {
        worktree_path
    } else {
        git_dir.parent()?.join(worktree_path)
    };
    Some(worktree_path.join("HEAD"))
}

fn watch_git_ref(git_head_path: &Path, git_ref: &str) {
    let Some(worktree_git_dir) = git_head_path.parent() else {
        return;
    };

    let common_dir_path = worktree_git_dir.join("commondir");
    let common_git_dir = if let Ok(common_dir) = fs::read_to_string(&common_dir_path) {
        println!("cargo:rerun-if-changed={}", common_dir_path.display());
        let common_dir = PathBuf::from(common_dir.trim());
        if common_dir.is_absolute() {
            common_dir
        } else {
            worktree_git_dir.join(common_dir)
        }
    } else {
        worktree_git_dir.to_path_buf()
    };

    let git_ref_path = common_git_dir.join(git_ref);
    if git_ref_path.exists() {
        println!("cargo:rerun-if-changed={}", git_ref_path.display());
    } else {
        let packed_refs = common_git_dir.join("packed-refs");
        if packed_refs.exists() {
            println!("cargo:rerun-if-changed={}", packed_refs.display());
        }
        if let Some(parent) = git_ref_path.ancestors().find(|parent| parent.is_dir()) {
            println!("cargo:rerun-if-changed={}", parent.display());
        }
    }
}
