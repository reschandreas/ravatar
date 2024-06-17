use crate::ldap::get_attributes_with_filter;
use crate::structs::Config;
use crate::{md5, sha256};
use filetime::FileTime;
use rand::random;
use rayon::iter::IntoParallelRefIterator;
use rayon::prelude::*;
use std::path::Path;
use std::time::Instant;
use std::{fs, vec};
use futures::channel::mpsc::{channel, Receiver};
use futures::executor::block_on;
use futures::{SinkExt, StreamExt};
use notify::event::{ModifyKind, RenameMode};
use notify::event::DataChange::Content;
use notify::{Event, PollWatcher, RecursiveMode, Watcher};
use image::io::Reader as ImageReader;
use crate::utils::{build_path, create_directory, get_filename, get_full_filename};

pub fn resize_default(config: &Config) {
    create_directory(Path::new(&config.images));
    let binding = build_path(
        vec![config.images.clone(), 512.to_string(), "mm".to_string()],
        Some(config.extension.clone()),
    );
    let path = binding.as_path();
    let binding = build_path(
        vec!["default".to_string(), "mm".to_string()],
        Some(config.extension.clone()),
    );
    let default = binding.as_path();
    if !needs_update(default, path) {
        log::info!("skipping default");
        return;
    }
    let sizes: Vec<u32> = vec![16, 32, 48, 64, 80, 96, 128, 256, 512];
    let extension = config.extension.clone();
    let image_path = config.images.clone();
    let source_binding = build_path(
        vec!["default".to_string(), "mm.".to_string()],
        Some(extension.clone()),
    );
    sizes.par_iter().for_each(|size| {
        let directory = build_path(vec![image_path.clone(), size.to_string()], None);
        create_directory(directory.as_path());
        let binding = build_path(
            vec![image_path.clone(), size.to_string(), "mm".to_string()],
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
        );
    });
}

pub async fn process_directory(directory: &Path, config: &Config) {
    for path in fs::read_dir(directory).unwrap().flatten() {
        process_image(&path.path(), config, false).await;
    }
}

pub async fn process_image(path: &Path, config: &Config, force: bool) {
    create_directory(Path::new(&config.images));
    if let Some(filename) = get_filename(path) {
        let binding = build_path(
            vec![config.images.to_string(), 512.to_string(), filename],
            Some(config.extension.clone()),
        );
        let image_path = binding.as_path();
        if !force && !needs_update(path, image_path) {
            log::info!("skipping {}", path.to_str().unwrap());
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
        println!("gotta clean up {} and all other links", md5_hash);
        let sizes: Vec<u32> = vec![16, 32, 48, 64, 80, 96, 128, 256, 512];
        let mut alternate_names = Vec::new();
        if config.ldap.is_some() {
            alternate_names = get_alternate_names_of(config.clone(), &filename).await;
        }
        alternate_names.push(sha256(&filename));
        sizes.iter().for_each(|size| {
            let size_path = build_path(vec![config.images.clone(), size.to_string()], None);
            let cache_path = build_path(
                vec![size_path.to_str().unwrap().to_string(), md5_hash.clone()],
                Some(config.extension.clone()),
            );
            for name in alternate_names.clone() {
                let link_path = build_path(
                    vec![size_path.to_str().unwrap().to_string(), name],
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
        });
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
            let alternate_names =
                get_alternate_names_of(config.clone(), &filename).await;

            let sizes: Vec<u32> = vec![16, 32, 48, 64, 80, 96, 128, 256, 512];
            log::info!("processing {}", source.to_str().unwrap());
            sizes.par_iter().for_each(|size| {
                let binding = build_path(vec![config.images.clone(), size.to_string()], None);
                let size_path = binding.as_path();
                create_directory(size_path);
                let binding = build_path(
                    vec![config.images.clone(), size.to_string(), md5_hash.clone()],
                    Some(config.extension.clone()),
                );

                let cache_path = binding.as_path();

                if !needs_update(source, cache_path) {
                    return;
                }
                resize_image(
                    source,
                    cache_path,
                    *size,
                    size_path,
                    alternate_names.clone(),
                    config.clone(),
                );
            });
            log::info!("resized {} in {:?}", filename, before.elapsed());
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
    for name in alternate_names {
        let link_path = build_path(
            vec![directory.to_str().unwrap().parse().unwrap(), name],
            Some(config.extension.clone()),
        );
        if !link_path.as_path().exists() {
            fs::hard_link(source, link_path.as_path()).unwrap();
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
        log::info!("locking {}", path.to_str().unwrap());
        return if !lock_path.as_path().exists() {
            let content = random::<u64>().to_string();
            fs::write(lock_path, content.clone()).expect("Could not write lock file");
            log::info!("locked {}", path.to_str().unwrap());
            Some(content)
        } else {
            log::warn!("Could not lock {}, already locked", path.to_str().unwrap());
            release_if_old_lock(lock_path.as_path());
            lock_image(path, config)
        };
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


fn async_watcher() -> notify::Result<(PollWatcher, Receiver<notify::Result<Event>>)> {
    let (mut tx, rx) = channel(1);

    let watcher = PollWatcher::new(
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

    if let Err(e) = async_watch(path, config).await {
        log::error!("error: {:?}", e);
    }
}

async fn async_watch<P: AsRef<Path>>(
    path: P,
    config: &Config,
) -> notify::Result<()> {
    let (mut watcher, mut rx) = async_watcher()?;

    watcher.watch(path.as_ref(), RecursiveMode::Recursive)?;

    while let Some(res) = rx.next().await {
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
) {
    if !Path::exists(source) {
        log::info!("source does not exist {}", source.to_str().unwrap());
        return;
    }
    let img = ImageReader::open(source).unwrap().decode();
    log::debug!("resizing {}", source.to_str().unwrap());
    img.expect("Can't read image")
        .resize_to_fill(size, size, image::imageops::FilterType::Lanczos3)
        .save_with_format(
            destination,
            image::ImageFormat::from_extension(config.extension.clone()).unwrap(),
        )
        .unwrap();
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
