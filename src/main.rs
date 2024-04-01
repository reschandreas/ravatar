mod config;

use std::path::{Path, PathBuf};
use std::thread;
use std::time::Instant;
use std::{env, fs};

use crate::config::Config;
use actix_web::http::StatusCode;
use actix_web::middleware::Logger;
use actix_web::web::Query;
use actix_web::{get, web, App, HttpResponse, HttpServer};
use filetime::FileTime;
use futures::{
    channel::mpsc::{channel, Receiver},
    SinkExt, StreamExt,
};
use image::io::Reader as ImageReader;
use md5::Md5;
use notify::event::DataChange::Content;
use notify::event::{ModifyKind, RenameMode};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use rayon::prelude::*;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Clone)]
struct AppState {
    config: Config,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let mut config = Config::default();
    let prefix: String = env::var("PATH_PREFIX").unwrap_or("/avatar".into());
    config.prefix = prefix.clone();
    config.raw = env::var("RAW_PATH").unwrap_or("./raw".into());
    config.images = env::var("IMAGES_PATH").unwrap_or("./images".into());
    if let Ok(port) = env::var("PORT").unwrap_or("".into()).parse() {
        config.port = port;
    } else {
        config.port = 8080;
    }
    let port: u16 = config.port;
    let cloned_config = config.clone();
    thread::spawn(move || {
        let raw_path = cloned_config.raw.clone();
        watch_directory(raw_path, cloned_config.clone());
    });
    let cloned_config = config.clone();
    thread::spawn(move || {
        println!("starting resizing");
        let binding = cloned_config.raw.clone();
        let raw_path = Path::new(&binding);
        resize_default(cloned_config.clone());
        process_directory(raw_path, cloned_config.clone());
    });
    let state = AppState {
        config: config.clone(),
    };
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    HttpServer::new(move || {
        App::new().wrap(Logger::default()).service(
            web::scope(&prefix)
                .app_data(web::Data::new(state.clone()))
                .service(avatar)
                .service(hash),
        )
    })
    .bind(("127.0.0.1", port))?
    .run()
    .await
}

#[get("/hash/{hash}")]
async fn hash(path: web::Path<(String,)>) -> HttpResponse {
    let mail = path.into_inner().0;
    let sha256 = sha256(mail.as_str());
    let md5 = md5(mail.as_str());
    HttpResponse::Ok().body(format!("{mail} {sha256} {md5}"))
}

#[derive(Debug, Deserialize, Clone)]
pub struct ImageRequest {
    s: Option<u16>,
    size: Option<u16>,
    d: Option<String>,
    default: Option<String>,
    forcedefault: Option<char>,
    f: Option<char>,
}

fn read_size(query: Query<ImageRequest>) -> u16 {
    if let Some(size_param) = query.s {
        return size_param;
    }
    if let Some(size_param) = query.size {
        return size_param;
    }
    80
}

fn read_default(query: Query<ImageRequest>) -> String {
    let mut default: String = "mm".to_string();
    if let Some(default_param) = &query.d {
        default = default_param.clone();
    }
    if let Some(default_param) = &query.default {
        default = default_param.clone();
    }
    if default.eq("mp") {
        default = "mm".to_string();
    }
    default
}

fn read_forcedefault(query: Query<ImageRequest>) -> bool {
    if let Some(force) = &query.forcedefault {
        return force.eq(&'y');
    }
    if let Some(force) = &query.f {
        return force.eq(&'y');
    }
    false
}

#[get("/{mail}")]
async fn avatar(
    path: web::Path<(String,)>,
    data: web::Data<AppState>,
    query: Query<ImageRequest>,
) -> HttpResponse {
    let mail_hash = path.into_inner().0;
    let config: Config = data.config.clone();
    let cache_dir = config.images;
    let size: u16 = read_size(query.clone());
    let default: String = read_default(query.clone());
    println!("serving {mail_hash}, size {size}");
    let mut path = build_path(
        vec![cache_dir.clone(), size.to_string(), mail_hash.clone()],
        Some("png".to_string()),
    );
    if !path.exists() || read_forcedefault(query) {
        println!("not found {mail_hash}, size {size}, serving {default}");
        match default.as_str() {
            "404" => {
                return HttpResponse::NotFound().finish();
            }
            "mm" => {
                path = build_path(
                    vec![cache_dir.clone(), size.to_string(), "mm".to_string()],
                    Some("png".to_string()),
                );
            }
            _ => {
                path = build_path(
                    vec![cache_dir.clone(), size.to_string(), default.clone()],
                    Some("png".to_string()),
                );
            }
        }
    }
    let image_content = web::block(move || fs::read(path)).await.unwrap().unwrap();
    HttpResponse::build(StatusCode::OK)
        .content_type("image/png")
        .body(image_content)
}

fn resize_default(config: Config) {
    let binding = build_path(
        vec![config.images.clone(), 512.to_string(), "mm".to_string()],
        Some("png".to_string()),
    );
    let path = binding.as_path();
    let binding = build_path(
        vec!["default".to_string(), "mm".to_string()],
        Some("png".to_string()),
    );
    let default = binding.as_path();
    if !needs_update(default, path) {
        return;
    }
    let sizes: Vec<u32> = vec![16, 32, 48, 64, 80, 96, 128, 256, 512];
    sizes.par_iter().for_each(|size| {
        let image_path = config.images.clone();
        create_directory(build_path(vec![image_path.clone(), size.to_string()], None).as_path());
        let binding = build_path(
            vec![image_path.clone(), size.to_string(), "mm".to_string()],
            Some("png".to_string()),
        );
        let path = binding.as_path();
        let binding = build_path(
            vec!["default".to_string(), "mm.".to_string()],
            Some("png".to_string()),
        );
        let default_path = binding.as_path();
        resize_image(default_path, path, *size, None);
    });
}

fn sha256(filename: &str) -> String {
    Sha256::digest(filename.as_bytes())
        .iter()
        .fold(String::new(), |mut acc, byte| {
            acc.push_str(&format!("{:02x}", byte));
            acc
        })
}

fn md5(filename: &str) -> String {
    Md5::digest(filename.as_bytes())
        .iter()
        .fold(String::new(), |mut acc, byte| {
            acc.push_str(&format!("{:02x}", byte));
            acc
        })
}

fn watch_directory(path: String, config: Config) {
    println!("watching {}", path);

    futures::executor::block_on(async {
        if let Err(e) = async_watch(path, config).await {
            println!("error: {:?}", e)
        }
    });
}

fn async_watcher() -> notify::Result<(RecommendedWatcher, Receiver<notify::Result<Event>>)> {
    let (mut tx, rx) = channel(1);

    let watcher = RecommendedWatcher::new(
        move |res| {
            futures::executor::block_on(async {
                tx.send(res).await.unwrap();
            })
        },
        notify::Config::default(),
    )?;

    Ok((watcher, rx))
}

async fn async_watch<P: AsRef<Path>>(path: P, config: Config) -> notify::Result<()> {
    let (mut watcher, mut rx) = async_watcher()?;

    // Add a path to be watched. All files and directories at that path and
    // below will be monitored for changes.
    watcher.watch(path.as_ref(), RecursiveMode::Recursive)?;

    while let Some(res) = rx.next().await {
        match res {
            Ok(event) => match event.kind {
                notify::EventKind::Modify(ModifyKind::Name(RenameMode::Any)) => {
                    println!("moved");
                    if !Path::new(path.as_ref()).exists() {
                        evacuate_image(&event.paths[0], config.clone());
                    } else {
                        processing_image(&event.paths[0], config.clone(), false);
                    }
                }
                notify::EventKind::Create(_) => {
                    println!("create");
                    processing_image(&event.paths[0], config.clone(), false);
                }
                notify::EventKind::Modify(ModifyKind::Data(Content)) => {
                    println!("modify");
                    update_image(&event.paths[0], config.clone());
                }
                notify::EventKind::Remove(_) => {
                    evacuate_image(&event.paths[0], config.clone());
                }
                _ => {}
            },
            Err(e) => println!("watch error: {:?}", e),
        }
    }

    Ok(())
}

fn process_directory(directory: &Path, config: Config) {
    let paths = fs::read_dir(directory).unwrap();

    for path in paths.flatten() {
        processing_image(&path.path(), config.clone(), false);
    }
}

fn processing_image(path: &Path, config: Config, force: bool) {
    create_directory(Path::new(&config.images));
    if let Some(filename) = get_filename(path) {
        let binding = build_path(
            vec![config.images.to_string(), 512.to_string(), filename],
            Some("png".to_string()),
        );
        let image_path = binding.as_path();
        if !force && !needs_update(path, image_path) {
            return;
        }

        handle_image(path, config.clone());
    }
}

fn handle_image(source: &Path, config: Config) {
    if let Some(filename) = get_filename(source) {
        let md5_hash = md5(&filename);
        let sha256 = sha256(&filename);

        let before = Instant::now();
        let sizes: Vec<u32> = vec![16, 32, 48, 64, 80, 96, 128, 256, 512];
        sizes.par_iter().for_each(|size| {
            let binding = build_path(vec![config.images.clone(), size.to_string()], None);
            let size_path = binding.as_path();
            create_directory(size_path);
            let binding = build_path(
                vec![config.images.clone(), size.to_string(), md5_hash.clone()],
                Some("png".to_string()),
            );

            let cache_path = binding.as_path();
            let binding = build_path(
                vec![config.images.clone(), size.to_string(), sha256.clone()],
                Some("png".to_string()),
            );

            let link_path = binding.as_path();
            if !needs_update(source, cache_path) {
                return;
            }
            println!("resizing {}", cache_path.to_str().unwrap());
            resize_image(source, cache_path, *size, Some(link_path));
            println!("resized {} in {:?}", filename, before.elapsed());
        });
    }
}

fn resize_image(source: &Path, destination: &Path, size: u32, link_path: Option<&Path>) {
    let img = ImageReader::open(source).unwrap().decode();
    println!("resizing {}", source.to_str().unwrap());
    img.expect("Cant read image")
        .resize_to_fill(size, size, image::imageops::FilterType::Lanczos3)
        .save(destination)
        .unwrap();
    if let Some(link_path) = link_path {
        fs::hard_link(destination, link_path).unwrap();
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

fn update_image(path: &Path, config: Config) {
    println!(
        "updating {} {}",
        path.to_str().unwrap(),
        get_full_filename(path).starts_with('.')
    );
    if get_full_filename(path).starts_with('.') || !Path::exists(Path::new(&path)) {
        return;
    }
    println!("updating {}", path.to_str().unwrap());
    processing_image(path, config, true);
}

fn evacuate_image(path: &Path, config: Config) {
    let filename = get_full_filename(path);
    if filename.starts_with('.') {
        return;
    }
    if let Some(extension) = get_extension(&filename) {
        let md5_hash = md5(&filename);
        let sha256 = sha256(&filename);
        let sizes: Vec<u32> = vec![16, 32, 48, 64, 80, 96, 128, 256, 512];
        sizes.par_iter().for_each(|size| {
            let size_path = build_path(vec![config.images.clone(), size.to_string()], None);
            let cache_path = build_path(
                vec![size_path.to_str().unwrap().to_string(), md5_hash.clone()],
                Some(extension.to_string()),
            );
            let link_path = build_path(
                vec![size_path.to_str().unwrap().to_string(), sha256.clone()],
                Some(extension.to_string()),
            );
            fs::remove_file(cache_path).unwrap();
            fs::remove_file(link_path).unwrap();
        });
    }
}

fn get_full_filename(path: &Path) -> String {
    path.to_str()
        .unwrap()
        .split('/')
        .last()
        .unwrap()
        .to_string()
}

fn get_filename(path: &Path) -> Option<String> {
    let filename = get_full_filename(path);
    if let Some(extension) = get_extension(&filename) {
        return Some(filename.replace(format!(".{extension}").as_str(), ""));
    }
    None
}

fn build_path(parts: Vec<String>, extension: Option<String>) -> PathBuf {
    let mut path = PathBuf::new();
    for part in parts {
        path.push(part);
    }
    if let Some(extension) = extension {
        path.set_extension(extension);
    }
    path
}

fn create_directory(path: &Path) {
    if path.exists() {
        return;
    }
    fs::create_dir_all(path).expect("Could not create directory");
}

fn get_extension(path: &str) -> Option<String> {
    let extension = Path::new(&path).extension();
    if let Some(extension) = extension {
        return Some(extension.to_str().unwrap().to_string());
    }
    None
}
