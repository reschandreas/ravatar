use crate::ldap::get_attributes_with_filter;
use crate::structs::Config;
use crate::utils::{build_path, create_directory, get_filename, get_full_filename};
use crate::{md5, sha256};
use filetime::FileTime;
use futures::channel::mpsc::{channel, Receiver};
use futures::executor::block_on;
use futures::{SinkExt, StreamExt};
use ldap3::tokio::time::{sleep, Duration};
use notify::event::DataChange::Content;
use notify::event::{ModifyKind, RenameMode};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use rand::random;
use rayon::iter::IntoParallelRefIterator;
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::time::Instant;
use std::{fs, vec};

pub fn resize_default(config: &Config) {
    create_directory(Path::new(&config.images));
    let extension = config.mm_extension.clone();
    let binding = build_path(
        vec![config.images.clone(), 1024.to_string(), "mm".to_string()],
        Some(extension.clone()),
    );
    let path = binding.as_path();
    let binding = build_path(
        vec!["default".to_string(), "mm".to_string()],
        Some(extension.clone()),
    );
    let default = binding.as_path();
    if !needs_update(default, path) {
        log::debug!("skipping default");
        return;
    }
    let sizes: Vec<u32> = vec![16, 24, 32, 48, 64, 80, 96, 128, 256, 512, 1024];
    let image_path = config.images.clone();
    for name in ["mm", "default"] {
        let source_binding = build_path(
            vec!["default".to_string(), name.to_string()],
            Some(extension.clone()),
        );
        if !source_binding.as_path().exists() {
            log::warn!("source does not exist {}", source_binding.to_str().unwrap());
            continue;
        }
        sizes.par_iter().for_each(|size| {
            let directory = build_path(vec![image_path.clone(), size.to_string()], None);
            if !directory.as_path().exists() {
                create_directory(directory.as_path());
            }
            let binding = build_path(
                vec![image_path.clone(), size.to_string(), name.to_string()],
                Some(extension.clone()),
            );
            let source_path = source_binding.as_path();
            let path = binding.as_path();
            resize_image(
                source_path,
                path,
                *size,
                directory.as_path(),
                Vec::default(),
                config.clone(),
                true,
            );
        });
    }
}

pub async fn process_directory(directory: &Path, config: &Config) {
    if !directory.exists() {
        create_directory(directory);
    }
    for path in fs::read_dir(directory).unwrap().flatten() {
        process_image(&path.path(), config, false).await;
    }
}

pub async fn process_image(path: &Path, config: &Config, force: bool) {
    create_directory(Path::new(&config.images));
    if let Some(filename) = get_filename(path) {
        let binding = build_path(
            vec![config.images.to_string(), 1024.to_string(), filename],
            Some(config.extension.clone()),
        );
        let image_path = binding.as_path();
        if !force && !needs_update(path, image_path) {
            log::debug!("skipping {}", path.to_str().unwrap());
            return;
        }
        handle_image(path, config).await;
    }
}

pub async fn update_image(path: &Path, config: &Config) {
    log::debug!(
        "updating {} {}",
        path.to_str().unwrap(),
        get_full_filename(path).starts_with('.')
    );
    if get_full_filename(path).starts_with('.') || !Path::exists(Path::new(&path)) {
        return;
    }
    log::debug!("updating {}", path.to_str().unwrap());
    process_image(path, config, true).await;
}

pub async fn evacuate_image(path: &Path, config: &Config) {
    log::info!("evacuating {}", path.to_str().unwrap());
    if let Some(filename) = get_filename(path) {
        if filename.starts_with('.') {
            return;
        }
        let md5_hash = md5(&filename);
        log::info!("cleaning up {} and all other links", md5_hash);
        let sizes: Vec<u32> = vec![16, 24, 32, 48, 64, 80, 96, 128, 256, 512, 1024];
        let mut alternate_names = Vec::new();
        if config.ldap.is_some() {
            alternate_names = get_alternate_names_of(config.clone(), &filename).await;
        }
        sizes.iter().for_each(|size| {
            let size_path = build_path(vec![config.images.clone(), size.to_string()], None);
            cleanup_image(config, size_path, md5_hash.clone(), alternate_names.clone());
            if config.offer_original_dimensions {
                let binding = build_path(
                    vec![
                        config.images.clone(),
                        "original-dimensions".to_string(),
                        size.to_string(),
                    ],
                    None,
                );
                cleanup_image(config, binding, md5_hash.clone(), alternate_names.clone());
            }
        });
    }
}

fn cleanup_image(config: &Config, path_prefix: PathBuf, md5_hash: String, names: Vec<String>) {
    let cache_path = build_path(
        vec![path_prefix.to_str().unwrap().to_string(), md5_hash.clone()],
        Some(config.extension.clone()),
    );
    for name in names.clone() {
        let link_path = build_path(
            vec![path_prefix.to_str().unwrap().to_string(), name],
            Some(config.extension.clone()),
        );
        if link_path.as_path().exists() {
            fs::remove_file(link_path).expect("Could not delete link");
        } else {
            log::info!("link not found {}", link_path.to_str().unwrap());
        }
    }
    if cache_path.as_path().exists() {
        fs::remove_file(cache_path).expect("Could not delete file");
    } else {
        log::info!("file not found {}", cache_path.to_str().unwrap());
    }
}

async fn get_alternate_names_of(config: Config, filename: &str) -> Vec<String> {
    let mut alternate_names = vec![sha256(filename)];
    if config.ldap.is_some() {
        for value in get_attributes_with_filter(config, filename)
            .await
            .unwrap_or_default()
        {
            alternate_names.push(md5(&value));
            alternate_names.push(sha256(&value));
        }
    }
    alternate_names
}

pub async fn handle_image(source: &Path, config: &Config) {
    if let Some(lock) = lock_image(source, config.clone()) {
        let before = Instant::now();
        if let Some(filename) = get_filename(source) {
            let md5_hash = md5(&filename);
            // let's find some more names for this image
            let alternate_names = get_alternate_names_of(config.clone(), &filename).await;

            let sizes: Vec<u32> = vec![16, 24, 32, 48, 64, 80, 96, 128, 256, 512, 1024];
            log::debug!("processing {}", source.to_str().unwrap());
            let was_resized: Vec<bool> = sizes.par_iter().map(|size| {
                let binding = build_path(vec![config.images.clone(), size.to_string()], None);
                let size_path = binding.as_path();
                if !size_path.exists() {
                    log::debug!("creating directory {}", size_path.to_str().unwrap());
                    create_directory(size_path);
                }
                let binding = build_path(
                    vec![config.images.clone(), size.to_string(), md5_hash.clone()],
                    Some(config.extension.clone()),
                );

                let cache_path = binding.as_path();

                if needs_update(source, cache_path) {
                    log::debug!("resizing {} to {}", source.to_str().unwrap(), size);
                    resize_image(
                        source,
                        cache_path,
                        *size,
                        size_path,
                        alternate_names.clone(),
                        config.clone(),
                        true,
                    );
                }
                if config.offer_original_dimensions {
                    let dimensions_path: PathBuf = build_path(
                        vec![config.images.clone(), "original-dimensions".to_string()],
                        None,
                    );
                    if !dimensions_path.exists() {
                        log::debug!("creating directory {}", dimensions_path.to_str().unwrap());
                        create_directory(dimensions_path.as_path());
                    }
                    let directory_binding = build_path(
                        vec![
                            config.images.clone(),
                            "original-dimensions".to_string(),
                            size.to_string(),
                        ],
                        None,
                    );
                    if !directory_binding.as_path().exists() {
                        log::debug!("creating directory {}", directory_binding.as_path().to_str().unwrap());
                        create_directory(directory_binding.as_path());
                    }
                    let binding = build_path(
                        vec![
                            config.images.clone(),
                            "original-dimensions".to_string(),
                            size.to_string(),
                            md5_hash.clone(),
                        ],
                        Some(config.extension.clone()),
                    );

                    let cache_path = binding.as_path();
                    log::debug!(
                        "resizing {} to {}",
                        source.to_str().unwrap(),
                        cache_path.to_str().unwrap()
                    );
                    if needs_update(source, cache_path) {
                        resize_image(
                            source,
                            cache_path,
                            *size,
                            directory_binding.as_path(),
                            alternate_names.clone(),
                            config.clone(),
                            false,
                        );
                        return true;
                    }
                }
                false
            }).collect();
            if was_resized.iter().any(|x| *x) {
                log::info!("resized {} in {:?}", filename, before.elapsed());
            }
        }
        unlock_image(source, config.clone(), lock);
    }
}

pub fn create_links_for_image(
    config: Config,
    directory: &Path,
    source: &Path,
    alternate_names: Vec<String>,
) {
    if !Path::exists(directory) {
        create_directory(directory);
    }
    for name in alternate_names {
        let target_directory = build_path(
            vec![directory.to_str().unwrap().parse().unwrap()],
            None,
        );
        if !Path::exists(target_directory.as_path()) {
            create_directory(target_directory.as_path());
        }
        let link_path = build_path(
            vec![directory.to_str().unwrap().parse().unwrap(), name],
            Some(config.extension.clone()),
        );
        if !link_path.as_path().exists() {
            log::debug!(
                "linking {} to {}",
                source.to_str().unwrap(),
                link_path.to_str().unwrap()
            );
            let result = fs::hard_link(source, link_path.as_path());
            if result.is_err() {
                log::error!(
                    "Could not create link {} to {}",
                    source.to_str().unwrap(),
                    link_path.to_str().unwrap()
                );
            }
        }
    }
}

fn lock_image(path: &Path, config: Config) -> Option<String> {
    if let Some(filename) = get_filename(path) {
        let md5_hash = md5(&filename);
        create_directory(
            build_path(vec![config.images.clone(), ".locks".to_string()], None).as_path(),
        );
        let lock_path = build_path(
            vec![
                config.images.clone(),
                ".locks".to_string(),
                md5_hash.clone(),
            ],
            Some("lock".to_string()),
        );
        log::debug!("locking {}", path.to_str()?);
        if !lock_path.as_path().exists() {
            let content = random::<u64>().to_string();
            fs::write(lock_path, content.clone()).expect("Could not write lock file");
            log::debug!("locked {}", path.to_str().unwrap());
            Some(content)
        } else {
            log::warn!("Could not lock {}, already locked", path.to_str()?);
            release_if_old_lock(lock_path.as_path());
            lock_image(path, config)
        }
    } else {
        None
    }
}

fn unlock_image(path: &Path, config: Config, content: String) {
    if let Some(filename) = get_filename(path) {
        let md5_hash = md5(&filename);
        let lock_path = build_path(
            vec![
                config.images.clone(),
                ".locks".to_string(),
                md5_hash.clone(),
            ],
            Some("lock".to_string()),
        );
        if lock_path.as_path().exists() {
            let file_content =
                fs::read_to_string(lock_path.clone()).expect("Could not read lock file");
            if file_content == content {
                fs::remove_file(lock_path).expect("Could not delete lock file");
            } else {
                log::warn!("Could not unlock {}, not my lock", path.to_str().unwrap());
                release_if_old_lock(lock_path.as_path());
            }
        }
    }
}

fn release_if_old_lock(path: &Path) {
    let metadata = fs::metadata(path).unwrap();
    let raw_mtime = FileTime::from_last_modification_time(&metadata);
    if raw_mtime.seconds() > 60 {
        fs::remove_file(path).unwrap()
    }
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

pub(crate) async fn watch_directory(path: String, config: &Config) {
    log::info!("watching {}", path);

    let path = Path::new(&path);

    if !path.exists() {
        create_directory(path);
    }

    if let Err(e) = async_watch(path, config).await {
        log::error!("error: {:?}", e);
    }
}

async fn async_watch<P: AsRef<Path>>(path: P, config: &Config) -> notify::Result<()> {
    let (mut watcher, mut rx) = async_watcher()?;

    watcher.watch(path.as_ref(), RecursiveMode::Recursive)?;

    while let Some(res) = rx.next().await {
        // wait a bit, to avoid being to eager
        sleep(Duration::from_millis(200 + random::<u64>() % 500)).await;
        match res {
            Ok(event) => match event.kind {
                notify::EventKind::Modify(ModifyKind::Name(RenameMode::Any)) => {
                    log::info!("a file was renamed");
                    if !path.as_ref().exists() {
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
                _ => {}
            },
            Err(e) => log::error!("watch error: {:?}", e),
        }
    }

    Ok(())
}

fn resize_image(
    source: &Path,
    destination: &Path,
    size: u32,
    directory: &Path,
    alternate_names: Vec<String>,
    config: Config,
    resize_to_fill: bool,
) {
    if !Path::exists(source) {
        log::info!("source does not exist {}", source.to_str().unwrap());
        return;
    }
    log::debug!("resizing {}", source.to_str().unwrap());
    let image_res = image::ImageReader::open(source);
    if image_res.is_err() {
        log::error!("Could not open image {}", source.to_str().unwrap());
        return;
    }
    let mut image = match image_res.unwrap().decode() {
        Ok(image) => image,
        Err(err) => {
            log::error!(
                "Failed to decode image: {} {}",
                err,
                source.to_str().unwrap()
            );
            return;
        }
    };

    if resize_to_fill {
        image = image.resize_to_fill(size, size, image::imageops::FilterType::Lanczos3);
    } else {
        image = image.resize(size, size, image::imageops::FilterType::Lanczos3);
    }

    let result = image.save_with_format(
        destination,
        image::ImageFormat::from_extension(config.extension.clone()).unwrap(),
    );
    if result.is_err() {
        log::error!(
            "Could not resize image {} and store to {}",
            source.to_str().unwrap(),
            destination.to_str().unwrap()
        );
        return;
    }
    if !alternate_names.is_empty() {
        create_links_for_image(config.clone(), directory, destination, alternate_names);
    }
}

fn needs_update(raw: &Path, processed: &Path) -> bool {
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
