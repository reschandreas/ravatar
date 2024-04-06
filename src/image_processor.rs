use std::fs;
use std::path::Path;
use std::time::Instant;
use rayon::iter::IntoParallelRefIterator;
use crate::{build_path, create_directory, get_filename, get_full_filename, md5, needs_update, resize_image, sha256};
use crate::structs::Config;
use rayon::prelude::*;

pub fn resize_default(config: Config) {
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
        return;
    }
    let sizes: Vec<u32> = vec![16, 32, 48, 64, 80, 96, 128, 256, 512];
    let extension = config.extension.clone();
    sizes.par_iter().for_each(|size| {
        let image_path = config.images.clone();
        create_directory(build_path(vec![image_path.clone(), size.to_string()], None).as_path());
        let binding = build_path(
            vec![image_path.clone(), size.to_string(), "mm".to_string()],
            Some(extension.clone()),
        );
        let path = binding.as_path();
        let binding = build_path(
            vec!["default".to_string(), "mm.".to_string()],
            Some(extension.clone()),
        );
        let default_path = binding.as_path();
        resize_image(default_path, path, *size, None, config.clone());
    });
}

pub fn process_directory(directory: &Path, config: Config) {
    for path in fs::read_dir(directory).unwrap().flatten() {
        processing_image(&path.path(), config.clone(), false);
    }
}

pub fn processing_image(path: &Path, config: Config, force: bool) {
    create_directory(Path::new(&config.images));
    if let Some(filename) = get_filename(path) {
        let binding = build_path(
            vec![config.images.to_string(), 512.to_string(), filename],
            Some(config.extension.clone()),
        );
        let image_path = binding.as_path();
        if !force && !needs_update(path, image_path) {
            return;
        }

        handle_image(path, config.clone());
    }
}

pub fn update_image(path: &Path, config: Config) {
    log::debug!(
        "updating {} {}",
        path.to_str().unwrap(),
        get_full_filename(path).starts_with('.')
    );
    if get_full_filename(path).starts_with('.') || !Path::exists(Path::new(&path)) {
        return;
    }
    log::debug!("updating {}", path.to_str().unwrap());
    processing_image(path, config, true);
}

pub fn evacuate_image(path: &Path, config: Config) {
    log::info!("evacuating {}", path.to_str().unwrap());
    if let Some(filename) = get_filename(path) {
        if filename.starts_with('.') || !get_full_filename(path).ends_with(&config.extension) {
            return;
        }
        let md5_hash = md5(&filename);
        let sha256 = sha256(&filename);
        println!("gotta clean up {} and {}", md5_hash, sha256);
        let sizes: Vec<u32> = vec![16, 32, 48, 64, 80, 96, 128, 256, 512];
        sizes.iter().for_each(|size| {
            let size_path = build_path(vec![config.images.clone(), size.to_string()], None);
            let cache_path = build_path(
                vec![size_path.to_str().unwrap().to_string(), md5_hash.clone()],
                Some(config.extension.clone()),
            );
            let link_path = build_path(
                vec![size_path.to_str().unwrap().to_string(), sha256.clone()],
                Some(config.extension.clone()),
            );
            if link_path.as_path().exists() {
                fs::remove_file(link_path).expect("Could not delete link");
            } else {
                log::info!("link not found {}", link_path.to_str().unwrap());
            }
            if cache_path.as_path().exists() {
                fs::remove_file(cache_path).expect("Could not delete file");
            } else {
                log::info!("file not found {}", cache_path.to_str().unwrap());
            }
        });
    }
}

pub fn handle_image(source: &Path, config: Config) {
    if let Some(filename) = get_filename(source) {
        let md5_hash = md5(&filename);
        let sha256 = sha256(&filename);

        let before = Instant::now();
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
            let binding = build_path(
                vec![config.images.clone(), size.to_string(), sha256.clone()],
                Some(config.extension.clone()),
            );

            if !needs_update(source, cache_path) {
                return;
            }
            let link_path = binding.as_path();
            resize_image(source, cache_path, *size, Some(link_path), config.clone());
            log::debug!("resized {} in {:?}", filename, before.elapsed());
        });
    }
}