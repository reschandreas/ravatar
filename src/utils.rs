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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_sha256() {
        assert_eq!(
            sha256("sha256"),
            "5d5b09f6dcb2d53a5fffc60c4ac0d55fabdf556069d6631545f42aa6e3500f2e".to_string()
        );
    }

    #[test]
    fn test_md5() {
        assert_eq!(md5("md5"), "1bc29b36f623ba82aaf6724fd3b16718".to_string());
    }

    #[test]
    fn test_create_directory() {
        let path = Path::new("test_create_directory");
        assert_eq!(path.exists(), false);
        create_directory(path);
        assert_eq!(path.exists(), true);
        create_directory(path);
        assert_eq!(path.exists(), true);
        fs::remove_dir(path).unwrap();
    }

    #[test]
    fn test_get_extension() {
        for extension in &["txt", "jpeg", "svg", "png"] {
            let control_path = &format!("testfile.{}", extension);
            let path = Path::new(control_path);
            assert_eq!(get_extension(path), Some(extension.to_string()));
        }
    }

    #[test]
    fn test_get_no_extension() {
        let control_path = &"testfile".to_string();
        let path = Path::new(control_path);
        assert_eq!(get_extension(path), None);
    }

    #[test]
    fn test_get_full_filename() {
        for extension in &["txt", "jpeg", "svg", "png"] {
            let path: PathBuf = [
                "some",
                "irrelevant.path",
                &format!("testfile.{}", extension),
            ]
            .iter()
            .collect();
            let filename = format!("testfile.{}", extension);
            assert_eq!(get_full_filename(path.as_path()), filename);
            let built_path = build_path(
                vec![
                    "some".to_string(),
                    "irrelevant.path".to_string(),
                    "testfile".to_string(),
                ],
                Some(extension.to_string()),
            );
            assert_eq!(get_full_filename(built_path.as_path()), filename);
        }
    }
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
    let buffer = path.to_path_buf();
    buffer.iter().last().unwrap().to_str().unwrap().to_string()
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
