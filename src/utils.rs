use md5::Md5;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn sha256(filename: &str) -> String {
    Sha256::digest(filename.as_bytes())
        .iter()
        .fold(String::new(), |mut acc, byte| {
            acc.push_str(&format!("{:02x}", byte));
            acc
        })
}

pub(crate) fn md5(filename: &str) -> String {
    Md5::digest(filename.as_bytes())
        .iter()
        .fold(String::new(), |mut acc, byte| {
            acc.push_str(&format!("{:02x}", byte));
            acc
        })
}

pub(crate) fn create_directory(path: &Path) {
    if path.exists() {
        return;
    }
    fs::create_dir_all(path).expect("Could not create directory");
}

pub(crate) fn get_extension(path: &Path) -> Option<String> {
    let extension = path.extension();
    if let Some(extension) = extension {
        return Some(extension.to_str()?.to_string());
    }
    None
}

pub(crate) fn get_full_filename(path: &Path) -> String {
    path.to_str()
        .unwrap()
        .split('/')
        .last()
        .unwrap()
        .to_string()
}

pub(crate) fn get_filename(path: &Path) -> Option<String> {
    let filename = get_full_filename(path);
    if let Some(extension) = get_extension(path) {
        return Some(
            filename
                .replace(format!(".{extension}").as_str(), "")
                .trim()
                .parse()
                .unwrap(),
        );
    }
    None
}

pub(crate) fn build_path(parts: Vec<String>, extension: Option<String>) -> PathBuf {
    let mut path = PathBuf::new();
    for part in parts {
        path.push(part);
    }
    if let Some(extension) = extension {
        path.set_extension(extension);
    }
    path
}
