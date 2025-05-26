use crate::image_processor::{evacuate_image, process_image, update_image};
use crate::structs::{Config, EnumerationResults};
use crate::utils::get_full_filename;
use async_trait::async_trait;
use azure_core::credentials::TokenCredential;
use azure_core::http::{RequestContent, StatusCode};
use azure_identity::DefaultAzureCredential;
use azure_storage_blob::models::BlobClientGetPropertiesResultHeaders;
use azure_storage_blob::{BlobClient, BlobClientOptions, BlockBlobClientUploadOptions};
use filetime::FileTime;
use futures::channel::mpsc::{channel, Receiver};
use futures::executor::block_on;
use futures::{SinkExt, StreamExt};
use notify::event::DataChange::Content;
use notify::event::{ModifyKind, RenameMode};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use rand::random;
use reqwest::header::{ACCEPT, AUTHORIZATION};
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use quick_xml::de::from_str;
use tokio::time::sleep;

#[derive(Clone, Debug)]
pub enum StorageBackendType {
    Local(LocalStorage),
    AzureBlob(AzureBlobStorage),
}

#[async_trait]
impl StorageBackend for StorageBackendType {
    fn get_location(&self) -> String {
        match self {
            StorageBackendType::Local(instance) => instance.get_location(),
            StorageBackendType::AzureBlob(instance) => instance.get_location(),
        }
    }

    fn get_raw(&self) -> String {
        match self {
            StorageBackendType::Local(instance) => instance.get_raw(),
            StorageBackendType::AzureBlob(instance) => instance.get_raw(),
        }
    }

    fn get_images(&self) -> String {
        match self {
            StorageBackendType::Local(instance) => instance.get_images(),
            StorageBackendType::AzureBlob(instance) => instance.get_images(),
        }
    }

    async fn read(&self, path: &Path) -> Result<Vec<u8>, String> {
        match self {
            StorageBackendType::Local(instance) => instance.read(path).await,
            StorageBackendType::AzureBlob(instance) => instance.read(path).await,
        }
    }

    async fn write(&self, path: &Path, data: &[u8]) -> Result<(), String> {
        match self {
            StorageBackendType::Local(instance) => instance.write(path, data).await,
            StorageBackendType::AzureBlob(instance) => instance.write(path, data).await,
        }
    }

    async fn delete(&self, path: &Path) -> Result<(), String> {
        match self {
            StorageBackendType::Local(instance) => instance.delete(path).await,
            StorageBackendType::AzureBlob(instance) => instance.delete(path).await,
        }
    }

    async fn create_directory(&self, path: &Path) -> Result<(), String> {
        match self {
            StorageBackendType::Local(instance) => instance.create_directory(path).await,
            StorageBackendType::AzureBlob(instance) => instance.create_directory(path).await,
        }
    }

    async fn needs_update(&self, raw: &Path, processed: &Path) -> bool {
        match self {
            StorageBackendType::Local(instance) => instance.needs_update(raw, processed).await,
            StorageBackendType::AzureBlob(instance) => instance.needs_update(raw, processed).await,
        }
    }

    async fn exists(&self, path: &Path) -> bool {
        match self {
            StorageBackendType::Local(instance) => instance.exists(path).await,
            StorageBackendType::AzureBlob(instance) => instance.exists(path).await,
        }
    }

    async fn last_modified(&self, path: &Path) -> Option<FileTime> {
        match self {
            StorageBackendType::Local(instance) => instance.last_modified(path).await,
            StorageBackendType::AzureBlob(instance) => instance.last_modified(path).await,
        }
    }

    async fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>, String> {
        match self {
            StorageBackendType::Local(instance) => instance.read_dir(path).await,
            StorageBackendType::AzureBlob(instance) => instance.read_dir(path).await,
        }
    }

    async fn async_watch(&self, path: PathBuf, config: &Config) -> notify::Result<()> {
        match self {
            StorageBackendType::Local(instance) => instance.async_watch(path, config).await,
            StorageBackendType::AzureBlob(_) => Ok(()),
        }
    }

    async fn copy(&self, src: &Path, dst: &Path) -> Result<u64, String> {
        match self {
            StorageBackendType::Local(instance) => instance.copy(src, dst).await,
            StorageBackendType::AzureBlob(instance) => instance.copy(src, dst).await,
        }
    }

    async fn hard_link(&self, src: &Path, dst: &Path) -> Result<(), String> {
        match self {
            StorageBackendType::Local(instance) => instance.hard_link(src, dst).await,
            StorageBackendType::AzureBlob(instance) => instance.hard_link(src, dst).await,
        }
    }
}

#[async_trait]
pub trait StorageBackend: Clone + Debug {
    fn get_location(&self) -> String;
    fn get_raw(&self) -> String;

    fn get_images(&self) -> String;

    async fn read(&self, path: &Path) -> Result<Vec<u8>, String>;
    async fn write(&self, path: &Path, data: &[u8]) -> Result<(), String>;
    async fn delete(&self, path: &Path) -> Result<(), String>;

    async fn create_directory(&self, path: &Path) -> Result<(), String>;

    async fn needs_update(&self, raw: &Path, processed: &Path) -> bool;

    async fn exists(&self, path: &Path) -> bool;

    async fn last_modified(&self, path: &Path) -> Option<FileTime>;

    async fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>, String>;

    async fn async_watch(&self, path: PathBuf, config: &Config) -> notify::Result<()>;

    async fn copy(&self, src: &Path, dst: &Path) -> Result<u64, String>;

    async fn hard_link(&self, src: &Path, dst: &Path) -> Result<(), String>;
}

#[derive(Default, Clone, Debug)]
pub struct AzureBlobStorage {
    location: String,
    raw: String,
    images: String,
}

#[derive(Default, Clone, Debug)]
pub struct LocalStorage {
    location: String,
    raw: String,
    images: String,
}

impl LocalStorage {
    // pub fn new(location: String, raw: String, images: String) -> Self {
    //     LocalStorage {
    //         location,
    //         raw,
    //         images,
    //     }
    // }
}

#[async_trait]
impl StorageBackend for LocalStorage {
    fn get_location(&self) -> String {
        self.location.clone()
    }

    fn get_raw(&self) -> String {
        self.raw.clone()
    }

    fn get_images(&self) -> String {
        self.images.clone()
    }

    async fn read(&self, path: &Path) -> Result<Vec<u8>, String> {
        let path = PathBuf::from(path);
        fs::read(path).map_err(|e| e.to_string())
    }

    async fn write(&self, path: &Path, data: &[u8]) -> Result<(), String> {
        let path = PathBuf::from(path);
        fs::write(path, data).map_err(|e| e.to_string())
    }

    async fn delete(&self, path: &Path) -> Result<(), String> {
        let path = PathBuf::from(path);
        fs::remove_file(path).map_err(|e| e.to_string())
    }

    async fn create_directory(&self, path: &Path) -> Result<(), String> {
        let path = PathBuf::from(path);
        if path.exists() {
            return Ok(());
        }
        fs::create_dir_all(path).map_err(|e| e.to_string())
    }

    async fn needs_update(&self, raw: &Path, processed: &Path) -> bool {
        let filename = get_full_filename(raw);
        if filename.starts_with('.') {
            return false;
        }

        if !Path::new(&processed).exists() || !Path::new(raw).exists() {
            return true;
        }

        let raw_metadata = fs::metadata(raw).unwrap();
        let raw_mtime = FileTime::from_last_modification_time(&raw_metadata);

        let processed_metadata = fs::metadata(processed).unwrap();
        let processed_mtime = FileTime::from_last_modification_time(&processed_metadata);
        raw_mtime > processed_mtime
    }

    async fn exists(&self, path: &Path) -> bool {
        let path = PathBuf::from(path);
        path.exists()
    }

    async fn last_modified(&self, path: &Path) -> Option<FileTime> {
        let path = PathBuf::from(path);
        if path.exists() {
            let metadata = fs::metadata(path).ok()?;
            Some(FileTime::from_last_modification_time(&metadata))
        } else {
            None
        }
    }

    async fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>, String> {
        if !path.exists() || !path.is_dir() {
            return Err(format!("Directory does not exist: {:?}", path));
        }
        fs::read_dir(path)
            .unwrap()
            .flatten()
            .filter(|entry| !entry.file_type().unwrap().is_dir())
            .filter(|entry| !entry.file_name().into_string().unwrap().starts_with("."))
            .map(|entry| {
                let path = entry.path();
                Ok(path)
            })
            .collect()
    }
    async fn async_watch(&self, path: PathBuf, config: &Config) -> notify::Result<()> {
        let (mut watcher, mut rx) = async_watcher()?;

        watcher.watch(path.as_ref(), RecursiveMode::Recursive)?;

        while let Some(res) = rx.next().await {
            // wait a bit, to avoid being to eager
            sleep(Duration::from_millis(200 + random::<u64>() % 500)).await;
            match res {
                Ok(event) => match event.kind {
                    notify::EventKind::Modify(ModifyKind::Name(RenameMode::Any)) => {
                        log::info!("a file was renamed");
                        if !self.exists(path.as_ref()).await {
                            evacuate_image(&event.paths[0], config).await;
                        } else {
                            process_image(&event.paths[0], config, false).await;
                        }
                    }
                    notify::EventKind::Create(_) => {
                        log::info!("found a new file");
                        process_image(&event.paths[0], config, false).await;
                    }
                    notify::EventKind::Modify(ModifyKind::Data(Content)) => {
                        log::info!("a file was updated");
                        update_image(&event.paths[0], config).await;
                    }
                    notify::EventKind::Remove(_) => {
                        log::info!("a file was removed");
                        evacuate_image(&event.paths[0], config).await;
                    }
                    _ => {
                        log::debug!("unhandled event: {:?}", event);
                    }
                },
                Err(e) => log::error!("watch error: {:?}", e),
            }
        }

        Ok(())
    }

    async fn copy(&self, src: &Path, dst: &Path) -> Result<u64, String> {
        fs::copy(src, dst).map_err(|e| e.to_string())
    }

    async fn hard_link(&self, src: &Path, dst: &Path) -> Result<(), String> {
        fs::hard_link(src, dst).map_err(|e| e.to_string())
    }
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

pub(crate) fn get_filename(path: &Path) -> Option<String> {
    path.file_stem()?.to_str().map(|s| s.to_string())
}

fn async_watcher() -> notify::Result<(RecommendedWatcher, Receiver<notify::Result<Event>>)> {
    let (mut tx, rx) = channel(1);

    let watcher = RecommendedWatcher::new(
        move |res| {
            block_on(async {
                tx.send(res).await.unwrap();
            })
        },
        notify::Config::default(),
    )?;

    Ok((watcher, rx))
}

impl AzureBlobStorage {
    pub fn new(location: String, raw: String, images: String) -> Self {
        AzureBlobStorage {
            location,
            raw: raw.trim_start_matches("./").to_string(),
            images: images.trim_start_matches("./").to_string(),
        }
    }

    fn is_raw(&self, path: &Path) -> bool {
        path.starts_with(&self.raw)
    }

    fn is_images(&self, path: &Path) -> bool {
        path.starts_with(&self.images)
    }

    fn get_container_name(&self, path: &Path) -> String {
        if self.is_raw(path) {
            self.raw.clone()
        } else if self.is_images(path) {
            self.images.clone()
        } else {
            println!("{:?}", path);
            panic!("Path does not match any container");
        }
    }

    fn create_blob_client(
        &self,
        storage_account_url: &str,
        container: &str,
        blob_path: &str,
    ) -> Option<BlobClient> {
        let credential = DefaultAzureCredential::builder().build().unwrap();
        let client = BlobClient::new(
            storage_account_url,
            container.to_string(),
            blob_path.to_string(),
            credential,
            Some(BlobClientOptions::default()),
        );
        if client.is_err() {
            log::error!("Failed to create BlobClient: {}", client.err().unwrap());
            None
        } else {
            // log::info!("Successfully created BlobClient");
            Some(client.unwrap())
        }
    }

    // pub(crate) fn create_source_blob_container_client(
    //     &self,
    //     config: &Config,
    // ) -> Option<BlobContainerClient> {
    //     config
    //         .storage_account_url
    //         .as_ref()
    //         .map(|storage_account_url| {
    //             self.create_blob_container_client(storage_account_url, &config.raw)
    //         })
    // }
    //
    // pub(crate) fn create_destination_blob_container_client(
    //     &self,
    //     config: &Config,
    // ) -> Option<BlobContainerClient> {
    //     config
    //         .storage_account_url
    //         .as_ref()
    //         .map(|storage_account_url| {
    //             self.create_blob_container_client(storage_account_url, &config.images)
    //         })
    // }
}

impl AzureBlobStorage {
    fn get_location(&self) -> String {
        self.location.clone()
    }

    fn get_raw(&self) -> String {
        self.raw.clone()
    }

    fn get_images(&self) -> String {
        self.images.clone()
    }

    async fn read(&self, path: &Path) -> Result<Vec<u8>, String> {
        let container_name = self.get_container_name(path);
        let blob_name_without_container = path.strip_prefix(&container_name).unwrap_or(path);
        let blob_client = self.create_blob_client(
            &self.location,
            &container_name,
            blob_name_without_container.to_str().unwrap(),
        );
        if let Some(blob) = blob_client {
            if let Ok(blob) = blob.download(None).await {
                return Ok(blob.into_raw_body().collect().await.unwrap().to_vec());
            }
        }
        Err(format!("Failed to create BlobClient for path: {}", path.display()))
        
        // let content = blob_client
        //     .unwrap()
        //     .download(None)
        //     .await
        //     .unwrap()
        //     .into_raw_body()
        //     .collect()
        //     .await
        //     .unwrap()
        //     .to_vec();
        // Ok(content)
    }

    async fn write(&self, path: &Path, data: &[u8]) -> Result<(), String> {
        let container_name = self.get_container_name(path);
        let blob_name_without_container = path.strip_prefix(&container_name).unwrap_or(path);
        let blob_client = self.create_blob_client(
            &self.location,
            &container_name,
            blob_name_without_container.to_str().unwrap(),
        );
        let mut options = BlockBlobClientUploadOptions::default();
        let extension = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        if !extension.is_empty() {
            options.blob_content_type = Some(format!("image/{}", extension));
        }
        let result = blob_client
            .unwrap()
            .upload(
                RequestContent::from(data.to_vec()),
                true,
                u64::try_from(data.len()).unwrap(),
                Some(options),
            )
            .await
            .map_err(|e| e.to_string());
        if let Err(e) = result {
            log::error!("Failed to write to Azure Blob Storage: {}", e);
            Err(e)
        } else {
            Ok(())
        }
    }

    async fn delete(&self, path: &Path) -> Result<(), String> {
        let container_name = self.get_container_name(path);
        let blob_name_without_container = path.strip_prefix(&container_name).unwrap_or(path);
        let blob_client = self.create_blob_client(
            &self.location,
            &container_name,
            blob_name_without_container.to_str().unwrap(),
        );
        let result = blob_client
            .unwrap()
            .delete(None)
            .await
            .map_err(|e| e.to_string());
        if let Err(e) = result {
            log::error!("Failed to write to Azure Blob Storage: {}", e);
            Err(e)
        } else {
            Ok(())
        }
    }

    async fn create_directory(&self, _: &Path) -> Result<(), String> {
        Ok(())
        // let container_name = self.get_container_name(path);
        // let blob_name_without_container = path.strip_prefix(&container_name).unwrap_or(path);
        // let blob_name = blob_name_without_container.to_str().unwrap();
        // if blob_name.is_empty() {
        //     return Ok(());
        // }
        //
        // let blob_name = if !blob_name.ends_with('/') {
        //     format!("{}/", blob_name)
        // } else {
        //     blob_name.to_string()
        // };
        //
        // let blob_client =
        //     self.create_blob_client(&self.location, &container_name, blob_name.as_str());
        // // Azure Blob Storage does not have directories, but we can create a "directory" by creating a blob with a trailing slash
        // let mock: Vec<u8> = Vec::new();
        // let content: RequestContent<bytes::Bytes> = RequestContent::from(mock);
        // let result = blob_client
        //     .unwrap()
        //     .upload(content, true, 0, None)
        //     .await
        //     .map_err(|e| e.to_string());
        // if let Err(e) = result {
        //     log::error!("Failed to write to Azure Blob Storage: {}", e);
        //     Err(e)
        // } else {
        //     Ok(())
        // }
    }

    async fn needs_update(&self, raw: &Path, processed: &Path) -> bool {
        let blob_client = self.create_blob_client(
            &self.location,
            &self.get_container_name(raw),
            raw.to_str().unwrap(),
        );
        if blob_client.is_none() {
            log::error!(
                "Failed to create BlobClient for raw path: {}",
                raw.display()
            );
            return true;
        }
        let blob_client = blob_client.unwrap();

        if !self.exists(raw).await {
            return true;
        }
        if let Ok(blob) = blob_client.get_properties(None).await {
            if blob.status() == StatusCode::NotFound {
                return true;
            }
            let last_modified = blob.last_modified().unwrap();
            let processed_blob_client = self.create_blob_client(
                &self.location,
                &self.get_container_name(processed),
                processed.to_str().unwrap(),
            );
            if processed_blob_client.is_none() {
                log::error!(
                "Failed to create BlobClient for processed path: {}",
                processed.display()
            );
                return true;
            }
            let processed_blob_client = processed_blob_client.unwrap();
            if let Ok(processed_blob) = processed_blob_client.get_properties(None).await {
                if processed_blob.status() == StatusCode::NotFound {
                    return true;
                }
                let last_modified_processed = processed_blob.last_modified()
                    .unwrap();
                last_modified.unwrap() >= last_modified_processed.unwrap()
            } else {
                true
            }
        } else {
            true
        }
    }

    async fn exists(&self, path: &Path) -> bool {
        let container_name = self.get_container_name(path);
        let blob_name_without_container = path.strip_prefix(&container_name).unwrap_or(path);
        let blob_name = blob_name_without_container.to_str().unwrap();
        let blob_client = self.create_blob_client(&self.location, &container_name, blob_name);
        if blob_client.is_none() {
            log::error!("Failed to create BlobClient for path: {}", path.display());
            return false;
        }
        if let Some(blob_client) = blob_client {
            let exists = blob_client.get_properties(None).await;
            if let Err(e) = exists {
                if e.http_status().unwrap() == StatusCode::NotFound {
                    // log::info!("Blob does not exist: {}", path.display());
                    return false;
                }
            }
        } else {
            log::error!("Failed to create BlobClient for path: {}", path.display());
            return false;
        }
        true
    }

    async fn last_modified(&self, path: &Path) -> Option<FileTime> {
        let container_name = self.get_container_name(path);
        let blob_name_without_container = path.strip_prefix(&container_name).unwrap_or(path);
        let blob_name = blob_name_without_container.to_str().unwrap();
        let blob_client = self.create_blob_client(&self.location, &container_name, blob_name);
        if let Some(blob_client) = blob_client {
            if let Ok(properties) = blob_client.get_properties(None).await {
                if let Ok(last_modified) = properties.last_modified() {
                    let last_modified = last_modified.unwrap();
                    let last_modified = last_modified.unix_timestamp();
                    return Some(FileTime::from_unix_time(last_modified, 0));
                }
            }
        }
        None
    }

    async fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>, String> {
        let credential = DefaultAzureCredential::builder().build().unwrap();

        let token_response = credential
            .get_token(&["https://storage.azure.com/.default"])
            .await
            .unwrap();

        let access_token = token_response.token.secret();

        let container = self.get_container_name(path);
        let prefix = path
            .strip_prefix(&container)
            .unwrap_or(path)
            .to_str()
            .unwrap_or("");

        let client = reqwest::Client::new();

        let list_url = format!(
            "{}/{}?restype=container&comp=list&prefix={}",
            self.location, container, prefix
        );

        let response = client
            .get(&list_url)
            .header(ACCEPT, "application/xml")
            .header(AUTHORIZATION, format!("Bearer {}", access_token))
            .header("x-ms-version", "2025-05-05")
            .header("x-ms-client-request-id", uuid::Uuid::new_v4().to_string())
            .send()
            .await
            .unwrap();

        let body = response.text().await.unwrap();
        
        let result: EnumerationResults = from_str(&body).unwrap();

        let mut blobs = vec![];
        if let Some(prefix) = result.blobs {
            if prefix.blob.is_none() {
                return Ok(blobs);
            }
            for blob in prefix.blob.unwrap() {
                let blob_name = blob.name;
                let full_path = PathBuf::from(&container).join(blob_name);
                blobs.push(full_path);
            }
        }

        Ok(blobs)
    }

    async fn copy(&self, src: &Path, dst: &Path) -> Result<u64, String> {
        let data = self.read(src).await?;
        self.write(dst, &data).await?;
        Ok(data.len() as u64)
    }

    async fn hard_link(&self, _: &Path, _: &Path) -> Result<(), String> {
        Err("Hard linking is not supported for Azure Blob Storage".to_string())
    }
}
