use crate::utils::get_full_filename;
use filetime::FileTime;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use futures::channel::mpsc::{channel, Receiver};
use futures::executor::block_on;
use futures::{SinkExt, StreamExt};
use notify::event::{ModifyKind, RenameMode};
use notify::event::DataChange::Content;
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use rand::random;
use tokio::time::sleep;
use crate::image_processor::{evacuate_image, process_image, update_image};
use crate::structs::Config;


pub trait StorageBackend {
    fn read(&self, path: &Path) -> Result<Vec<u8>, String>;
    fn write(&self, path: &Path, data: &[u8]) -> Result<(), String>;
    fn delete(&self, path: &Path) -> Result<(), String>;

    fn create_directory(&self, path: &Path) -> Result<(), String>;

    fn needs_update(&self, raw: &Path, processed: &Path) -> bool;

    fn exists(&self, path: &Path) -> bool;

    fn last_modified(&self, path: &Path) -> Option<FileTime>;

    fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>, String>;
    
    async fn async_watch<P: AsRef<Path>>(&self, path: P, config: &Config) -> notify::Result<()>;
    
    fn copy(&self, src: &Path, dst: &Path) -> Result<u64, String>;
    
    fn hard_link(&self, src: &Path, dst: &Path) -> Result<(), String>;
}

#[derive(Default, Clone, Debug)]
pub struct AzureBlobStorage {
    account_url: String,
    container_name: String,
}

#[derive(Default, Clone, Debug)]
pub struct LocalStorage {}

impl StorageBackend for LocalStorage {
    fn read(&self, path: &Path) -> Result<Vec<u8>, String> {
        let path = PathBuf::from(path);
        fs::read(path).map_err(|e| e.to_string())
    }

    fn write(&self, path: &Path, data: &[u8]) -> Result<(), String> {
        let path = PathBuf::from(path);
        fs::write(path, data).map_err(|e| e.to_string())
    }

    fn delete(&self, path: &Path) -> Result<(), String> {
        let path = PathBuf::from(path);
        fs::remove_file(path).map_err(|e| e.to_string())
    }

    fn create_directory(&self, path: &Path) -> Result<(), String> {
        let path = PathBuf::from(path);
        if path.exists() {
            return Ok(());
        }
        fs::create_dir_all(path).map_err(|e| e.to_string())
    }

    fn needs_update(&self, raw: &Path, processed: &Path) -> bool {
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

    fn exists(&self, path: &Path) -> bool {
        let path = PathBuf::from(path);
        path.exists()
    }

    fn last_modified(&self, path: &Path) -> Option<FileTime> {
        let path = PathBuf::from(path);
        if path.exists() {
            let metadata = fs::metadata(path).ok()?;
            Some(FileTime::from_last_modification_time(&metadata))
        } else {
            None
        }
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>, String> {
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
    async fn async_watch<P: AsRef<Path>>(&self, path: P, config: &Config) -> notify::Result<()> {
        let (mut watcher, mut rx) = async_watcher()?;

        watcher.watch(path.as_ref(), RecursiveMode::Recursive)?;

        while let Some(res) = rx.next().await {
            // wait a bit, to avoid being to eager
            sleep(Duration::from_millis(200 + random::<u64>() % 500)).await;
            match res {
                Ok(event) => match event.kind {
                    notify::EventKind::Modify(ModifyKind::Name(RenameMode::Any)) => {
                        log::info!("a file was renamed");
                        if !self.exists(path.as_ref()) {
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

    fn copy(&self, src: &Path, dst: &Path) -> Result<u64, String> {
        fs::copy(src, dst).map_err(|e| e.to_string())
    }

    fn hard_link(&self, src: &Path, dst: &Path) -> Result<(), String> {
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