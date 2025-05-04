use crate::structs::Config;
use azure_core::http::RequestContent;
use azure_identity::DefaultAzureCredential;
use azure_storage_blob::{
    BlobClient, BlobClientOptions, BlobContainerClient, BlobContainerClientOptions,
};
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
    buffer
        .iter()
        .next_back()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

fn create_blob_container_client(storage_account_url: &str, container: &str) -> BlobContainerClient {
    let credential = DefaultAzureCredential::new().unwrap();
    BlobContainerClient::new(
        storage_account_url,
        container.to_string(),
        credential,
        Some(BlobContainerClientOptions::default()),
    )
    .unwrap()
}

fn create_blob_client(storage_account_url: &str, container: &str, blob_path: &str) -> BlobClient {
    let credential = DefaultAzureCredential::new().unwrap();
    BlobClient::new(
        storage_account_url,
        container.to_string(),
        blob_path.to_string(),
        credential,
        Some(BlobClientOptions::default()),
    )
    .unwrap()
}

pub(crate) fn create_source_blob_container_client(config: &Config) -> Option<BlobContainerClient> {
    config.storage_account_url.as_ref().map(|storage_account_url| create_blob_container_client(
            storage_account_url,
            &config.raw,
        ))
}

pub(crate) fn create_destination_blob_container_client(
    config: &Config,
) -> Option<BlobContainerClient> {
    config.storage_account_url.as_ref().map(|storage_account_url| create_blob_container_client(
            storage_account_url,
            &config.images,
        ))
}

/**
 * Check if a path exists locally or in Azure Blob Storage.
 */

pub(crate) fn path_exists(path: &Path, config: &Config) -> bool {
    if let Some(storage_account_url) = &config.storage_account_url {
        let container = match path.starts_with(&config.images) {
            true => &config.images,
            false => &config.raw,
        };
        let blob_name = path.to_str().unwrap();
        let _blob_client = create_blob_client(storage_account_url, container, blob_name);
    }
    path.exists()
}

pub(crate) async fn write_file(path: &Path, content: &[u8], config: &Config) {
    if let Some(storage_account_url) = &config.storage_account_url {
        let container = match path.starts_with(&config.images) {
            true => &config.images,
            false => &config.raw,
        };
        let blob_name = path.to_str().unwrap();
        let blob_client = create_blob_client(storage_account_url, container, blob_name);
        blob_client
            .upload(
                RequestContent::from(content.to_vec()),
                true,
                content.len().try_into().unwrap(),
                None,
            )
            .await
            .expect("Could not upload file");
    } else {
        fs::write(path, content).expect("Could not write file");
    }
}

pub(crate) async fn read_file(path: PathBuf, config: Config) -> Result<Vec<u8>, std::io::Error> {
    if let Some(storage_account_url) = &config.storage_account_url {
        let container = match path.starts_with(&config.images) {
            true => &config.images,
            false => &config.raw,
        };
        let blob_name = path.to_str().unwrap();
        let blob_client = create_blob_client(storage_account_url, container, blob_name);
        let response = blob_client.download(None).await;
        if let Ok(response) = response {
            return Ok(response.into_raw_body().collect().await.unwrap().to_vec());
        }
    } else if path.exists() {
        return fs::read(path);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "File not found",
    ))
}

#[cfg(test)]
mod tests {
    use crate::io::build_path;
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
        assert_eq!(
            md5_of_content(control_path),
            "1bc29b36f623ba82aaf6724fd3b16718".to_string()
        );
        fs::remove_file(path).unwrap();
    }
}
