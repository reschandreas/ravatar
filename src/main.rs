mod config;

use std::{env, fs};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Instant;

use actix_web::{App, get, HttpResponse, HttpServer, web};
use actix_web::http::StatusCode;
use actix_web::web::Query;
use filetime::FileTime;
use futures::{
    channel::mpsc::{channel, Receiver},
    SinkExt, StreamExt,
};
use image::io::Reader as ImageReader;
use md5::Md5;
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use notify::event::DataChange::Content;
use notify::event::ModifyKind;
use sha2::{Digest, Sha256};
use serde::Deserialize;
use crate::config::Config;

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
        let raw_path = cloned_config.raw.clone();
        resize_default(cloned_config.clone());
        cache_directory(raw_path.clone(), cloned_config.clone());
    });
    let state = AppState {
        config: config.clone(),
    };
    HttpServer::new(move || {
        App::new().service(web::scope(&prefix)
            .app_data(web::Data::new(state.clone()))
            .service(avatar)
        )
    })
        .bind(("127.0.0.1", port))?
        .run()
        .await
}

#[get("/hash/{hash}")]
async fn hash(path: web::Path<(String, )>) -> HttpResponse {
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
    f: Option<char>
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
async fn avatar(path: web::Path<(String, )>, data: web::Data<AppState>, query: Query<ImageRequest>) -> HttpResponse {
    let mail_hash = path.into_inner().0;
    let config: Config = data.config.clone();
    let cache_dir = config.images;
    let size: u16 = read_size(query.clone());
    let default: String = read_default(query.clone());
    println!("serving {mail_hash}, size {size}");
    let mut path = build_path(vec![cache_dir.clone(), size.to_string(), mail_hash.clone()], Some("png".to_string()));
    if !path.exists() || read_forcedefault(query) {
        println!("not found {mail_hash}, size {size}, serving {default}");
        match default.as_str() {
            "404" => {
                return HttpResponse::NotFound().finish();
            }
            "mm" => {
                path = build_path(vec![cache_dir.clone(), size.to_string(), "mm".to_string()], Some("png".to_string()));
            }
            _ => {
                path = build_path(vec![cache_dir.clone(), size.to_string(), default.clone()], Some("png".to_string()));
            }
        }
    }
    let image_content = web::block(move || fs::read(path)).await.unwrap().unwrap();
    HttpResponse::build(StatusCode::OK)
        .content_type("image/png")
        .body(image_content)
}

fn resize_default(config: Config) {
    let path = build_path(vec![config.images.clone(), 512.to_string(), "mm".to_string()], Some("png".to_string()));
    if !needs_update(&config.raw, path.to_str().unwrap()) {
        return;
    }
    let mut handles = vec![];
    for size in [16, 32, 48, 64, 80, 96, 128, 256, 512].iter() {
        let image_path = config.images.clone();
        create_directory(build_path(vec![image_path.clone(), size.to_string()], None));
        handles.push(thread::spawn(move || {
            let path = build_path(vec![image_path.clone(), size.to_string(), "mm".to_string()], Some("png".to_string()));
            let default_path = build_path(vec!["default".to_string(), "mm.".to_string()], Some("png".to_string()));
            resize_image(default_path.to_str().unwrap().to_string(), path.to_str().unwrap().to_string(), *size, None).join().unwrap();
        }));
    };
    for handle in handles {
        handle.join().unwrap();
    }
}

fn sha256(filename: &str) -> String {
    let hex_digest = Sha256::digest(filename.as_bytes())
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>();
    hex_digest
}

fn md5(filename: &str) -> String {
    let hex_digest = Md5::digest(filename.as_bytes())
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>();
    hex_digest
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
                notify::EventKind::Create(_) => {
                    let path = event.paths[0].to_str().unwrap().to_string();
                    cache_image(path, config.clone());
                }
                notify::EventKind::Modify(ModifyKind::Data(Content)) => {
                    let path = event.paths[0].to_str().unwrap().to_string();
                    update_image(path);
                }
                notify::EventKind::Remove(_) => {
                    let path = event.paths[0].to_str().unwrap().to_string();
                    evacuate_image(path);
                }
                _ => {}
            },
            Err(e) => println!("watch error: {:?}", e),
        }
    }

    Ok(())
}

fn cache_directory(path: String, config: Config) {
    let paths = fs::read_dir(path).unwrap();

    for path in paths {
        cache_image(path.unwrap().path().to_str().unwrap().to_string(), config.clone());
    }
}

fn cache_image(path: String, config: Config) {
    create_directory(PathBuf::from(&config.images));
    let filename = get_filename(&path);
    let image_path = build_path(vec![config.images.to_string(), 512.to_string(), filename], Some("png".to_string()));
    if !needs_update(&path, image_path.to_str().unwrap()) {
        return;
    }
    println!("caching {}", path);

    handle_image(path, config.clone());
}

fn handle_image(source: String, config: Config) {
    let filename = get_filename(&source);
    let md5_hash = md5(&filename);
    let sha256 = sha256(&filename);

    let before = Instant::now();
    let mut handles = vec![];
    for size in [16, 32, 48, 64, 80, 96, 128, 256, 512].iter() {
        let size_path = build_path(vec![config.images.clone(), size.to_string()], None);
        create_directory(size_path.clone());
        let cache_path = build_path(vec![config.images.clone(), size.to_string(), md5_hash.clone()], Some("png".to_string())).to_str().unwrap().to_string();
        let link_path = build_path(vec![config.images.clone(), size.to_string(), sha256.clone()], Some("png".to_string())).to_str().unwrap().to_string();
        if !needs_update(&source, &cache_path) {
            return;
        }
        println!("resizing {}", cache_path);
        handles.push(resize_image(source.clone(), cache_path.clone(), *size, Some(link_path)));
    }
    for handle in handles {
        handle.join().unwrap();
    }
    println!("resized {} in {:?}", filename, before.elapsed());
}

fn resize_image(source: String, destination: String, size: u32, link_path: Option<String>) -> thread::JoinHandle<()> {
    let img = ImageReader::open(&source).unwrap().decode();
    println!("resizing {}", source);
    thread::spawn(move || {
        img.expect("Cant read image")
            .resize_to_fill(size, size, image::imageops::FilterType::Lanczos3)
            .save_with_format(destination.clone(), image::ImageFormat::Png)
            .unwrap();
        if let Some(link_path) = link_path {
            fs::hard_link(destination.clone(), link_path).unwrap();
        }
    })
}

fn needs_update(path: &str, compare: &str) -> bool {
    let filename = get_full_filename(path);
    if filename.starts_with('.') {
        return false;
    }

    if !Path::new(&compare).exists() {
        return true;
    }

    let raw_metadata = fs::metadata(path).unwrap();
    let raw_mtime = FileTime::from_last_modification_time(&raw_metadata);

    if !Path::new(&compare).exists() {
        return true;
    }
    let cache_metadata = fs::metadata(compare).unwrap();
    let cache_mtime = FileTime::from_last_modification_time(&cache_metadata);
    raw_mtime > cache_mtime
}

fn update_image(path: String) {
    println!("updating {}", path);
}

fn evacuate_image(path: String) {
    if get_full_filename(&path).starts_with('.') {
        return;
    }
    println!("evacuating {}", path);
}

fn get_full_filename(path: &str) -> String {
    path.split('/').last().unwrap().to_string()
}

fn get_filename(path: &str) -> String {
    println!("path: {}", path);
    let filename = get_full_filename(path);
    let extension = Path::new(&path).extension();
    if let Some(extension) = extension {
        return filename.replace(format!(".{}", extension.to_str().unwrap()).as_str(), "")
    }
    filename
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

fn create_directory(path: PathBuf) {
    if path.exists() {
        return;
    }
    fs::create_dir_all(path).expect("Could not create directory");
}
