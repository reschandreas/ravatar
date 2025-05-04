use crate::io::{build_path, get_filename, StorageBackend};
use crate::ldap::get_attributes_with_filter;
use crate::structs::Format::{Portrait, Square};
use crate::structs::{Config, FaceLocation, Format, ResizableImage};
use crate::utils::{create_directory, get_full_filename};
use crate::{md5, sha256};
use futures::future::join_all;
use futures::StreamExt;
use notify::Watcher;
use rand::random;
use random_word::Lang;
use rayon::iter::IntoParallelRefIterator;
use rayon::prelude::*;
use resvg::tiny_skia::Pixmap;
use resvg::usvg::Tree;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufReader, Cursor, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;
use std::{fs, vec};
use tempfile::env;
use tokio::task;

pub async fn resize_default(config: &Config) {
    let storage_backend = config.storage_backend.clone().unwrap();
    storage_backend
        .create_directory(PathBuf::from(&config.images).as_path())
        .expect("Could not create directory");

    let extension = config.mm_extension.clone();

    let default_path = build_path(
        vec!["default".to_string(), "mm".to_string()],
        Some(extension.clone()),
    );

    let target_path = build_path(
        vec![
            config.images.clone(),
            config.default_format.as_str().to_string(),
            1024.to_string(),
            "mm".to_string(),
        ],
        Some(extension.clone()),
    );

    if !storage_backend.needs_update(default_path.as_path(), target_path.as_path()) {
        log::info!("skipping default");
        return;
    }

    let image_path = config.images.clone();
    for name in ["mm", "default"] {
        let source_path = build_path(
            vec!["default".to_string(), name.to_string()],
            Some(extension.clone()),
        );

        if !storage_backend.exists(source_path.as_path()) {
            log::warn!("source does not exist {}", source_path.to_string_lossy());
            continue;
        }

        let formats = config.formats.clone();
        let sizes = config.sizes.clone();

        for size in sizes {
            for format in formats.clone() {
                let directory = build_path(
                    vec![
                        image_path.clone(),
                        format.as_str().to_string(),
                        size.to_string(),
                    ],
                    None,
                );

                storage_backend
                    .create_directory(directory.as_path())
                    .unwrap();

                let destination_path = build_path(
                    vec![
                        image_path.clone(),
                        format.as_str().to_string(),
                        size.to_string(),
                        name.to_string(),
                    ],
                    Some(config.extension.clone()),
                );

                let resizable_image = ResizableImage {
                    source: source_path.as_path().to_path_buf(),
                    destination: destination_path.as_path().to_path_buf(),
                    size,
                    alternate_names: Vec::new(),
                    face_location: None,
                };

                let c = config.clone();
                task::spawn(async move {
                    resize_image(resizable_image, directory.as_path(), c.clone(), &Square).await;
                });
            }
        }
    }
}

pub async fn process_directory(directory: &Path, config: &Config) {
    let storage_backend = config.storage_backend.clone().unwrap();

    storage_backend.create_directory(directory).unwrap();

    let inventory: Vec<String> = read_inventory(&config.clone());
    let mut handled_files: Vec<String> = Vec::new();
    for path in storage_backend.read_dir(directory).unwrap() {
        // we are only interested in files with extensions
        if path.extension().is_some() {
            process_image(&path, config, false).await;
            let filename = get_filename(path.as_path()).unwrap();
            handled_files.push(filename);
        }
    }
    write_inventory(handled_files.clone(), config);
    let mut missing_files: Vec<String> = Vec::new();
    for asset in inventory {
        if !handled_files.contains(&asset) {
            missing_files.push(asset);
        }
    }
    for missing in missing_files {
        let path = build_path(Vec::from([config.images.clone(), missing]), None);
        evacuate_image(path.as_path(), config).await;
    }
}

pub fn read_inventory(config: &Config) -> Vec<String> {
    let storage_backend = config.storage_backend.clone().unwrap();
    let target_directory = config.images.clone();
    let path = build_path(
        Vec::from([target_directory.to_string(), "inventory.json".to_string()]),
        None,
    );
    let lock = lock_image(path.as_path(), config.clone());
    if lock.is_some() && storage_backend.exists(path.as_path()) {
        let data = String::from_utf8(
            storage_backend
                .read(path.as_path())
                .expect("Unable to read file"),
        )
        .unwrap();
        unlock_image(path.as_path(), config.clone(), lock.unwrap());
        let stuff: Vec<String> = serde_json::from_str(&data).expect("Unable to parse");
        return stuff;
    }
    Vec::new()
}

pub fn write_inventory(files: Vec<String>, config: &Config) {
    let storage_backend = config.storage_backend.clone().unwrap();
    let target_directory = config.images.clone();
    let path = build_path(
        Vec::from([target_directory.to_string(), "inventory.json".to_string()]),
        None,
    );
    let lock = lock_image(path.as_path(), config.clone());
    if lock.is_some() {
        let file = File::create(path.as_path()).expect("Failed to create or open the file");
        storage_backend
            .write(
                path.as_path(),
                serde_json::to_string(&files).unwrap().as_bytes(),
            )
            .expect("Failed to write empty file");
        unlock_image(path.as_path(), config.clone(), lock.unwrap());
    }
}

pub async fn process_image(path: &Path, config: &Config, force: bool) {
    let storage_backend = config.storage_backend.clone().unwrap();
    storage_backend
        .create_directory(Path::new(&config.images))
        .unwrap();
    if let Some(filename) = get_filename(path) {
        let binding = build_path(
            vec![config.images.to_string(), 1024.to_string(), filename],
            Some(config.extension.clone()),
        );
        let image_path = binding.as_path();
        if !force && !storage_backend.needs_update(path, image_path) {
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
    let storage_backend = config.storage_backend.clone().unwrap();
    for name in names {
        let link_path = build_path(
            vec![path_prefix.to_str().unwrap().to_string(), name],
            Some(config.extension.clone()),
        );
        if storage_backend.exists(link_path.as_path()) {
            storage_backend
                .delete(link_path.as_path())
                .expect("Could not delete link");
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
    let storage_backend = config.storage_backend.clone().unwrap();
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
                if storage_backend.needs_update(source, path.as_path()) {
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
            )
            .await;
        }
        unlock_image(source, config.clone(), lock);
    }
}

async fn parallel_resize_image(
    before: Instant,
    filename: String,
    image: &Path,
    md5_hash: String,
    config: Config,
    face_data: Option<FaceLocation>,
    alternate_names: Vec<String>,
) -> bool {
    let sizes = config.sizes.clone();
    let formats = config.formats.clone();
    let was_resized: Vec<_> = sizes
        .into_iter()
        .map(|size| {
            let config = config.clone();
            let image = image.to_path_buf();
            let md5_hash = md5_hash.clone();
            let alternate_names = alternate_names.clone();
            let f = formats.clone();

            task::spawn(async move {
                let was_resized_format: Vec<_> = f
                    .into_iter()
                    .map(|format| {
                        let config = config.clone();
                        let image = image.clone();
                        let md5_hash = md5_hash.clone();
                        let alternate_names = alternate_names.clone();
                        let face_data = face_data;

                        task::spawn(async move {
                            let storage_backend = config.storage_backend.clone().unwrap();
                            let mut path = vec![
                                config.images.clone(),
                                format.as_str().to_string(),
                                size.to_string(),
                            ];
                            let binding = build_path(path.clone(), None);
                            let size_path = binding.as_path();
                            storage_backend
                                .create_directory(size_path)
                                .expect("Could not create directory");

                            path.push(md5_hash.clone());
                            let binding = build_path(path, Some(config.extension.clone()));

                            let cache_path = binding.as_path();

                            if storage_backend.needs_update(&image, cache_path) {
                                log::debug!("resizing {} to {}", image.to_str().unwrap(), size);
                                let resizable_image = ResizableImage {
                                    source: image.clone(),
                                    destination: cache_path.to_path_buf(),
                                    size,
                                    alternate_names: alternate_names.clone(),
                                    face_location: face_data,
                                };
                                resize_image(resizable_image, size_path, config.clone(), &format)
                                    .await;
                                return true;
                            }
                            false
                        })
                    })
                    .collect::<Vec<_>>();

                let results = join_all(was_resized_format).await;
                results.into_iter().any(|x| x.expect("Failed to join task"))
            })
        })
        .collect::<Vec<_>>();

    let results = join_all(was_resized).await;
    if results.into_iter().any(|x| x.expect("Failed to join task")) {
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
    if !alternate_names.is_empty() {
        return;
    }
    let storage_backend = config.storage_backend.clone().unwrap();
    if !storage_backend.exists(directory) {
        storage_backend
            .create_directory(directory)
            .expect("Could not create directory");
    }
    for name in alternate_names {
        let target_directory = build_path(vec![directory.to_str().unwrap().parse().unwrap()], None);
        storage_backend
            .create_directory(target_directory.as_path())
            .expect("Could not create directory");
        let link_path = build_path(
            vec![directory.to_str().unwrap().parse().unwrap(), name],
            Some(config.extension.clone()),
        );
        if !storage_backend.exists(link_path.as_path()) {
            log::debug!(
                "linking {} to {}",
                source.to_str().unwrap(),
                link_path.to_str().unwrap()
            );
            let result = storage_backend.hard_link(source, link_path.as_path());
            if result.is_err() {
                log::debug!(
                    "Could not create link {} to {}, copying instead",
                    source.to_str().unwrap(),
                    link_path.to_str().unwrap()
                );
                storage_backend
                    .copy(source, link_path.as_path())
                    .expect("Could not copy file");
            }
        }
    }
}

fn lock_image(path: &Path, config: Config) -> Option<String> {
    let storage_backend = config.storage_backend.clone().unwrap();
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

        if !storage_backend.exists(lock_path.as_path()) {
            let content = random::<u64>().to_string();
            storage_backend
                .write(lock_path.as_path(), content.as_bytes())
                .expect("Could not write lock file");
            log::debug!("locked {}", path.to_str().unwrap());
            Some(content)
        } else {
            log::warn!("Could not lock {}, already locked", path.to_str()?);
            release_if_old_lock(lock_path.as_path(), &config);
            lock_image(path, config)
        }
    } else {
        None
    }
}

fn unlock_image(path: &Path, config: Config, content: String) {
    let storage_backend = config.storage_backend.clone().unwrap();
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
        if storage_backend.exists(lock_path.as_path()) {
            let file_content = String::from_utf8(
                storage_backend
                    .read(lock_path.as_path())
                    .expect("Could not read lock file"),
            )
            .unwrap();
            if file_content == content {
                storage_backend
                    .delete(lock_path.as_path())
                    .expect("Could not delete lock file");
            } else {
                log::warn!("Could not unlock {}, not my lock", path.to_str().unwrap());
                release_if_old_lock(lock_path.as_path(), &config);
            }
        }
    }
}

fn release_if_old_lock(path: &Path, config: &Config) {
    let storage_backend = config.storage_backend.clone().unwrap();
    let raw_mtime = storage_backend.last_modified(path).unwrap();
    if raw_mtime.seconds() > 60 {
        storage_backend
            .delete(path)
            .expect("Could not delete lock file");
    }
}

pub(crate) async fn watch_directory(path: String, config: &Config) {
    let storage_backend = config.clone().storage_backend.unwrap();
    log::info!("watching {}", path);

    let path = Path::new(&path);

    if !storage_backend.exists(path) {
        storage_backend
            .create_directory(path)
            .expect("Could not create directory");
    }

    if let Err(e) = storage_backend.async_watch(path, config).await {
        log::error!("error: {:?}", e);
    }
}

async fn resize_image(
    resizable_image: ResizableImage,
    directory: &Path,
    config: Config,
    format: &Format,
) {
    let storage_backend = config.storage_backend.clone().unwrap();
    let source = resizable_image.source.as_path();
    if !storage_backend.exists(source) {
        log::info!("source does not exist {}", source.to_str().unwrap());
        return;
    }
    let mut path: &Path = resizable_image.source.as_path();
    let mut temp_file: Option<PathBuf> = None;
    if path.extension() == Some(OsStr::new("svg")) {
        log::debug!("found a svg file");
        let word = random_word::get(Lang::En);
        let binding = build_path(
            vec![
                env::temp_dir().to_str().unwrap().parse().unwrap(),
                word.to_string(),
            ],
            Some("png".to_string()),
        );
        temp_file = Some(binding.as_path().to_path_buf());
        svg_to_png(
            source.to_str().unwrap(),
            binding.to_str().unwrap(),
            config.clone(),
        );
        path = temp_file.as_ref().unwrap().as_path();
        log::debug!("converted svg to png so we can resize it");
    }
    log::info!("resizing {}", source.to_str().unwrap());
    let content = storage_backend.read(path).expect("Could not read source");
    let image_res = image::ImageReader::new(BufReader::new(Cursor::new(content)))
        .with_guessed_format()
        .unwrap();

    let mut image = match image_res.decode() {
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
        if let Some(face) = resizable_image.face_location {
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
        image = image.resize_to_fill(
            resizable_image.size,
            resizable_image.size,
            image::imageops::FilterType::Lanczos3,
        );
    } else if format == &Portrait {
        image = image.crop(0, 0, image.width(), image.width());
        image = image.resize(
            resizable_image.size,
            resizable_image.size,
            image::imageops::FilterType::Lanczos3,
        );
    } else {
        image = image.resize(
            resizable_image.size,
            resizable_image.size,
            image::imageops::FilterType::Lanczos3,
        );
    }

    let result = image.save_with_format(
        resizable_image.destination.clone(),
        image::ImageFormat::from_extension(config.extension.clone()).unwrap(),
    );
    if result.is_err() {
        log::error!(
            "Could not resize image {} and store to {}",
            source.to_str().unwrap(),
            resizable_image.destination.as_path().to_str().unwrap()
        );
        return;
    }

    create_links_for_image(
        config.clone(),
        directory,
        resizable_image.destination.as_path(),
        resizable_image.alternate_names,
    );

    if let Some(temp_file) = temp_file {
        storage_backend
            .delete(temp_file.as_path())
            .expect("Could not delete file");
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

fn svg_to_png(source: &str, output_path: &str, config: Config) {
    let storage_backend = config.storage_backend.clone().unwrap();
    // Parse SVG data into a tree
    let opt = resvg::usvg::Options::default();
    let content = storage_backend
        .read(PathBuf::from(source).as_path())
        .expect("Could not read source");
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
            log::info!("Svg to {}.", output_path);
            let file = tempfile::NamedTempFile::new().unwrap();
            pixmap.save_png(file.path()).unwrap();
            let content = storage_backend.read(file.path()).unwrap();
            storage_backend
                .write(PathBuf::from(output_path).as_path(), &content)
                .expect("Could not write file");
            fs::remove_file(file.path()).unwrap();
        } else {
            log::error!("Failed to create pixmap");
        }
    } else {
        log::error!("Could not parse svg data {}", source);
    }
}

mod tests {
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use crate::structs::Format::*;
    use ldap3::tokio;
    #[allow(unused_imports)]
    use std::fs;
    #[allow(unused_imports)]
    use std::path::{Path, PathBuf};
    

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
            scan_interval: 10,
            watch_directories: false,
            storage_account_url: None,
            storage_backend: Some(LocalStorage::default()),
        };
        let mut hash_to_size = Vec::new();

        //hardcoded values to see if the resizing is consistent, need to be changed if images are changed
        for format in [Center, Square, Portrait] {
            hash_to_size.push((format, 1024, "285545e752f052f8170f91463719ab4f"));
            hash_to_size.push((format, 512, "45056602872523e2a671274ef59e59b2"));
            hash_to_size.push((format, 256, "fdac5ef6eaaccb0b29d35b63ef1fa030"));
            hash_to_size.push((format, 128, "01875e1e8b71df4fe61984d8f7833eb2"));
            hash_to_size.push((format, 64, "30a09121e95111c0c2d1a19dd23c05dd"));
        }

        //delete all the files
        if fs::exists(config.images.clone()).expect("directory not found") {
            fs::remove_dir_all(config.images.clone()).unwrap();
        }

        resize_default(&config).await;

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
            assert!(path.exists());

            use crate::utils::md5_of_content;
            assert_eq!(md5_of_content(path.to_str().unwrap()), hash);
        }

        //delete all the files
        fs::remove_dir_all(config.images).unwrap()
    }

    #[tokio::test]
    async fn test_lenna_resize() {
        let input_images = ["resources", "test", "images"].iter().collect::<PathBuf>();
        let raw_images = ["resources", "test", "raw"].iter().collect::<PathBuf>();
        let converted_images = ["resources", "test", "converted"]
            .iter()
            .collect::<PathBuf>();
        if fs::exists(&converted_images).expect("REASON") {
            fs::remove_dir_all(&converted_images).unwrap();
        }
        fs::create_dir(&converted_images).unwrap();
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
            watch_directories: true,
            scan_interval: 10,
            storage_account_url: None,
            storage_backend: None,
        };

        let mut path = raw_images.join("lenna.png");

        // process_directory(&converted_images, &config).await;
        let files = fs::read_dir(&converted_images).unwrap();
        assert_eq!(files.count(), 0);

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
        let files = fs::read_dir(path).unwrap();
        // directories for each format should appear and a .locks directory, and the inventory file
        assert_eq!(files.count(), config.formats.len() + 2);
        for directory in fs::read_dir(path).unwrap().flatten() {
            let directory_name = directory.file_name();
            let name = directory_name.to_str().unwrap();
            if name == ".locks" || name == "inventory.json" {
                continue;
            }
            assert!(directory.file_type().unwrap().is_dir());
            assert!(config.formats.iter().any(|format| name == format.as_str()));
        }
    }
}
