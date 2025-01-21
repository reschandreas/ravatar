use crate::ldap::get_attributes_with_filter;
use crate::structs::Format::{Portrait, Square};
use crate::structs::{Config, FaceLocation, Format};
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
use random_word::Lang;
use rayon::iter::IntoParallelRefIterator;
use rayon::prelude::*;
use resvg::tiny_skia::Pixmap;
use resvg::usvg::Tree;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Instant;
use std::{fs, vec};

pub fn resize_default(config: &Config) {
    create_directory(Path::new(&config.images));
    let extension = config.mm_extension.clone();
    let binding = build_path(
        vec![
            config.images.clone(),
            config.default_format.as_str().parse().unwrap(),
            1024.to_string(),
            "mm".to_string(),
        ],
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
        config.sizes.par_iter().for_each(|size| {
            config.formats.par_iter().for_each(|format| {
                let directory = build_path(
                    vec![
                        image_path.clone(),
                        format.as_str().parse().unwrap(),
                        size.to_string(),
                    ],
                    None,
                );
                create_directory(directory.as_path());
                let binding = build_path(
                    vec![
                        image_path.clone(),
                        format.as_str().parse().unwrap(),
                        size.to_string(),
                        name.to_string(),
                    ],
                    Some(config.extension.clone()),
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
                    &Square,
                    None,
                );
            });
        });
    }
}

pub async fn process_directory(directory: &Path, config: &Config) {
    create_directory(directory);
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
        let sha256_hash = sha256(&filename);
        log::info!("cleaning up {} and all other links", md5_hash);
        let mut alternate_names = Vec::new();
        if config.ldap.is_some() {
            alternate_names = get_alternate_names_of(config.clone(), &filename).await;
        }
        alternate_names.push(sha256_hash.clone());
        alternate_names.push(md5_hash.clone());
        config.sizes.iter().for_each(|size| {
            config.formats.par_iter().for_each(|format| {
                let binding = build_path(
                    vec![
                        config.images.clone(),
                        format.as_str().to_string(),
                        size.to_string(),
                    ],
                    None,
                );
                cleanup_image(config, binding, alternate_names.clone());
            });
        });
    }
}

fn cleanup_image(config: &Config, path_prefix: PathBuf, names: Vec<String>) {
    for name in names {
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

            log::debug!("processing {}", source.to_str().unwrap());
            let mut face_data: Option<FaceLocation> = None;
            if config.formats.contains(&Format::Center) {
                let random_size = *config.sizes.last().unwrap();
                let path = build_path(
                    vec![
                        config.images.clone(),
                        Format::Center.as_str().to_string(),
                        random_size.to_string(),
                        md5_hash.clone(),
                    ],
                    Some(config.extension.clone()),
                );
                if needs_update(source, path.as_path()) {
                    face_data = detect_face_in_image(source);
                    if face_data.is_none() {
                        log::info!("no face found in image {}", source.to_str().unwrap());
                    }
                }
            }
            let alternate_names = get_alternate_names_of(config.clone(), &filename).await;
            parallel_resize_image(
                before,
                filename,
                source,
                md5_hash.clone(),
                config.clone(),
                face_data,
                alternate_names.clone(),
            );
        }
        unlock_image(source, config.clone(), lock);
    }
}

fn parallel_resize_image(
    before: Instant,
    filename: String,
    image: &Path,
    md5_hash: String,
    config: Config,
    face_data: Option<FaceLocation>,
    alternate_names: Vec<String>,
) -> bool {
    let was_resized: Vec<bool> = config
        .sizes
        .par_iter()
        .map(|size| {
            let was_resized_format: Vec<bool> = config
                .formats
                .par_iter()
                .map(|format| {
                    let mut path = vec![
                        config.images.clone(),
                        format.as_str().to_string(),
                        size.to_string(),
                    ];
                    let binding = build_path(path.clone(), None);
                    let size_path = binding.as_path();
                    create_directory(size_path);

                    path.push(md5_hash.clone());
                    let binding = build_path(path, Some(config.extension.clone()));

                    let cache_path = binding.as_path();

                    if needs_update(image, cache_path) {
                        log::debug!("resizing {} to {}", image.to_str().unwrap(), size);
                        resize_image(
                            image,
                            cache_path,
                            *size,
                            size_path,
                            alternate_names.clone(),
                            config.clone(),
                            format,
                            face_data,
                        );
                        return true;
                    }
                    false
                })
                .collect();
            if was_resized_format.iter().any(|x| *x) {
                return true;
            }
            false
        })
        .collect();
    if was_resized.iter().any(|x| *x) {
        log::info!("resized {} in {:?}", filename, before.elapsed());
        return true;
    }
    false
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
        let target_directory = build_path(vec![directory.to_str().unwrap().parse().unwrap()], None);
        create_directory(target_directory.as_path());
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
                log::info!(
                    "Could not create link {} to {}, copying instead",
                    source.to_str().unwrap(),
                    link_path.to_str().unwrap()
                );
                fs::copy(source, link_path.as_path()).expect("Could not copy file");
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
                _ => {
                    log::debug!("unhandled event: {:?}", event);
                }
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
    format: &Format,
    face_location: Option<FaceLocation>,
) {
    if !Path::exists(source) {
        log::info!("source does not exist {}", source.to_str().unwrap());
        return;
    }
    let mut path: &Path = source;
    let mut temp_file: Option<PathBuf> = None;
    if path.extension() == Some(OsStr::new("svg")) {
        log::debug!("found a svg file");
        let word = random_word::gen(Lang::En);
        let binding = build_path(
            vec!["/tmp".to_string(), word.to_string()],
            Some("png".to_string()),
        );
        temp_file = Some(binding.as_path().to_path_buf());
        svg_to_png(source.to_str().unwrap(), binding.to_str().unwrap());
        path = temp_file.as_ref().unwrap().as_path();
        log::debug!("converted svg to png so we can resize it");
    }
    log::debug!("resizing {}", source.to_str().unwrap());
    let image_res = image::ImageReader::open(path);
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

    if format == &Format::Center && image.width() != image.height() {
        if let Some(face) = face_location {
            log::debug!(
                "Found face in image {} at {:?}",
                source.to_str().unwrap(),
                face
            );
            let face_x = face.left;
            let face_y = face.top;
            let face_width = face.right - face.left;
            let face_height = face.bottom - face.top;
            // now lets make sure to somehow center the face
            let face_center_x = face_x + face_width / 2;
            let face_center_y = face_y + face_height / 2;
            let new_width: f64 = face_width as f64 * 1.6180333;
            let new_x: u32 = if face_center_x > new_width as u32 {
                (face_center_x as f64 - new_width) as u32
            } else {
                0
            };
            let new_height: f64 = face_height as f64 * (1.6180333 / 1.2f64);
            let new_y: u32 = if face_center_y > new_height as u32 {
                (face_center_y as f64 - new_height) as u32
            } else {
                0u32
            };
            let new_width = 3 * face_width;
            let new_height = 3 * face_height;
            image = image.crop_imm(new_x, new_y, new_width, new_height);
        }
    }

    if format == &Square || format == &Format::Center {
        image = image.resize_to_fill(size, size, image::imageops::FilterType::Lanczos3);
    } else if format == &Portrait {
        image = image.crop(0, 0, image.width(), image.width());
        image = image.resize(size, size, image::imageops::FilterType::Lanczos3);
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
    if let Some(temp_file) = temp_file {
        fs::remove_file(temp_file.as_path()).unwrap()
    }
}

#[cfg(feature = "face_recognition")]
fn detect_face_in_image(source: &Path) -> Option<FaceLocation> {
    use dlib_face_recognition::*;
    if let Ok(image) = image_dlib::open(source) {
        let matrix = ImageMatrix::from_image(&image.to_rgb8());
        let detector = FaceDetector::default();
        let face_locations = detector.face_locations(&matrix);

        if face_locations.is_empty() {
            log::debug!("No faces found in {:?}", source);
            return None;
        }
        if face_locations.len() > 1 {
            log::debug!("Multiple faces found in {:?}", source);
            return None;
        }

        let face_location = face_locations[0];

        return Some(FaceLocation {
            top: face_location.top.try_into().unwrap(),
            right: face_location.right.try_into().unwrap(),
            bottom: face_location.bottom.try_into().unwrap(),
            left: face_location.left.try_into().unwrap(),
        });
    }
    None
}

#[cfg(not(feature = "face_recognition"))]
fn detect_face_in_image(_source: &Path) -> Option<FaceLocation> {
    None
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

fn svg_to_png(source: &str, output_path: &str) {
    // Parse SVG data into a tree
    let opt = resvg::usvg::Options::default();
    let content = fs::read(source).unwrap();
    if let Ok(rtree) = Tree::from_data(&content, &opt) {
        // Set up the render target
        if let Some(mut pixmap) =
            Pixmap::new(rtree.size().width() as u32, rtree.size().height() as u32)
        {
            // Render the SVG
            resvg::render(
                &rtree,
                resvg::tiny_skia::Transform::default(),
                &mut pixmap.as_mut(),
            );

            // Save the output as PNG
            log::debug!("Svg to {}.", output_path);
            pixmap.save_png(output_path).unwrap();
        } else {
            log::error!("Failed to create pixmap");
        }
    } else {
        log::error!("Could not parse svg data {}", source);
    }
}

mod tests {
    #[allow(unused_imports)]
    use std::fs;
    #[allow(unused_imports)]
    use std::path::{Path, PathBuf};
    use ldap3::tokio;
    #[allow(unused_imports)]
    use crate::structs::Format::*;
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_resize_default() {
        let config = Config {
            host: "".to_string(),
            port: 8080,
            prefix: "".to_string(),
            images: "images".to_string(),
            default_format: Square,
            mm_extension: "png".to_string(),
            sizes: vec![64, 128, 256, 512, 1024],
            formats: vec![Center, Square, Portrait],
            extension: "png".to_string(),
            ldap: None,
            raw: "".to_string(),
            log_level: "".to_string(),
        };

        resize_default(&config);
        let mut hash_to_size = Vec::new();
        //hardcoded values to see if the resizing is consistent, need to be changed if images are changed
        hash_to_size.push((Center, 1024, "285545e752f052f8170f91463719ab4f"));
        hash_to_size.push((Center, 512, "45056602872523e2a671274ef59e59b2"));
        hash_to_size.push((Center, 256, "fdac5ef6eaaccb0b29d35b63ef1fa030"));
        hash_to_size.push((Center, 128, "01875e1e8b71df4fe61984d8f7833eb2"));
        hash_to_size.push((Center, 64, "30a09121e95111c0c2d1a19dd23c05dd"));

        hash_to_size.push((Square, 1024, "285545e752f052f8170f91463719ab4f"));
        hash_to_size.push((Square, 512, "45056602872523e2a671274ef59e59b2"));
        hash_to_size.push((Square, 256, "fdac5ef6eaaccb0b29d35b63ef1fa030"));
        hash_to_size.push((Square, 128, "01875e1e8b71df4fe61984d8f7833eb2"));
        hash_to_size.push((Square, 64, "30a09121e95111c0c2d1a19dd23c05dd"));

        hash_to_size.push((Portrait, 1024, "285545e752f052f8170f91463719ab4f"));
        hash_to_size.push((Portrait, 512, "45056602872523e2a671274ef59e59b2"));
        hash_to_size.push((Portrait, 256, "fdac5ef6eaaccb0b29d35b63ef1fa030"));
        hash_to_size.push((Portrait, 128, "01875e1e8b71df4fe61984d8f7833eb2"));
        hash_to_size.push((Portrait, 64, "30a09121e95111c0c2d1a19dd23c05dd"));

        for (format, size, hash) in hash_to_size {
            let binding = build_path(
                vec![
                    config.images.clone(),
                    format.as_str().to_string(),
                    size.to_string(),
                    "mm".to_string(),
                ],
                Some(config.mm_extension.clone()),
            );
            let path = binding.as_path();
            println!("checking {}", path.to_str().unwrap());
            assert_eq!(path.exists(), true);

            use crate::utils::md5_of_content;
            assert_eq!(md5_of_content(path.to_str().unwrap()), hash);
        }

        //delete all the files
        fs::remove_dir_all(config.images).unwrap()
    }

    #[tokio::test]
    async fn test_lenna_resize() {
        let input_images = PathBuf::from(["resources", "test", "images"].iter().collect::<PathBuf>());
        let raw_images = PathBuf::from(["resources", "test", "raw"].iter().collect::<PathBuf>());
        let converted_images = PathBuf::from(["resources", "test", "converted"].iter().collect::<PathBuf>());
        let config = Config {
            host: "".to_string(),
            port: 8080,
            prefix: "".to_string(),
            images: converted_images.to_str().unwrap().to_string(),
            default_format: Square,
            mm_extension: "png".to_string(),
            sizes: vec![64, 128, 256, 512, 1024],
            formats: vec![Center, Square, Portrait],
            extension: "png".to_string(),
            ldap: None,
            raw: raw_images.to_str().unwrap().to_string(),
            log_level: "".to_string(),
        };

        let mut path = raw_images.join("lenna.png");

        process_directory(&converted_images, &config).await;
        let files = fs::read_dir(&converted_images).unwrap();
        assert_eq!(files.count(), 0);

        // watch_directory(raw_images.to_str().unwrap().to_string(), &config).await;

        fs::copy(input_images.join("lenna.png"), path).unwrap();

        process_directory(&raw_images, &config).await;

        check_directories(&converted_images, &config);

        path = raw_images.join("monroe.svg");
        fs::copy(input_images.join("monroe.svg"), path).unwrap();

        process_directory(&raw_images, &config).await;
        check_directories(&converted_images, &config);
        fs::remove_dir_all(&converted_images).unwrap()
    }

    #[cfg(test)]
    fn check_directories(path: &Path, config: &Config) {
        let files = fs::read_dir(&path).unwrap();
        // directories for each format should appear and a .locks directory
        assert_eq!(files.count(), config.formats.len() + 1);
        for directory in fs::read_dir(&path).unwrap() {
            if let Ok(directory) = directory {
                let directory_name = directory.file_name();
                let name = directory_name.to_str().unwrap();
                assert!(directory.file_type().unwrap().is_dir());
                if name == ".locks" {
                    continue;
                }
                assert!(config.formats.iter().any(|format| name == format.as_str()));
            }
        }
    }
}
