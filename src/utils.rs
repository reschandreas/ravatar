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

#[cfg(test)]
pub(crate) fn md5_of_content(filename: &str) -> String {
    let content = fs::read(filename).expect("Could not read file");
    Md5::digest(&content)
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

pub(crate) fn get_full_filename(path: &Path) -> String {
    let buffer = path.to_path_buf();
    buffer.iter().next_back().unwrap().to_str().unwrap().to_string()
}

pub(crate) fn get_filename(path: &Path) -> Option<String> {
    path.file_stem()?.to_str().map(|s| s.to_string())
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
        assert!(!path.exists());
        create_directory(path);
        assert!(path.exists());
        create_directory(path);
        assert!(path.exists());
        fs::remove_dir(path).unwrap();
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

    #[test]
    fn test_md5_of_content() {
        let control_path = "md5_testfile.txt";
        let path = Path::new(control_path);
        fs::write(path, "md5").expect("Could not write file");
        assert_eq!(md5_of_content(control_path), "1bc29b36f623ba82aaf6724fd3b16718".to_string());
        fs::remove_file(path).unwrap();
    }
}
