mod image_processor;
mod ldap;
mod structs;
mod config;
mod utils;

use std::path::{Path, PathBuf};
use std::thread;
use std::fs;

use crate::image_processor::{
    create_links_for_image, evacuate_image, process_directory, process_image, resize_default,
    update_image,
};
use crate::structs::{AppState, Config, ImageRequest};
use actix_web::http::StatusCode;
use actix_web::middleware::Logger;
use actix_web::web::Query;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use filetime::FileTime;
use futures::executor::block_on;
use futures::{
    channel::mpsc::{channel, Receiver},
    SinkExt, StreamExt,
};
use image::io::Reader as ImageReader;
use ldap3::Ldap;
use notify::event::DataChange::Content;
use notify::event::{ModifyKind, RenameMode};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use crate::config::{read_config, read_default, read_force_default, read_size};
use crate::utils::{md5, sha256};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = read_config();
    let ldap = match ldap::connect_ldap(config.clone()).await {
        Ok(ldap) => Some(ldap),
        Err(e) => {
            log::error!("could not connect to ldap: {:?}", e);
            None
        }
    };
    let ldap_clone = ldap.clone();
    let cloned_config = config.clone();
    thread::spawn(move || {
        log::info!("starting resizing");
        let binding = cloned_config.raw.clone();
        let raw_path = Path::new(&binding);
        resize_default(&cloned_config);
        block_on(process_directory(raw_path, &cloned_config, ldap_clone));
    });
    let cloned_config = config.clone();
    let ldap_clone = ldap.clone();
    thread::spawn(move || {
        let raw_path = cloned_config.raw.clone();
        watch_directory(raw_path, &cloned_config, ldap_clone);
    });
    let host = config.host.clone();
    let port: u16 = config.port;
    let state = AppState {
        config,
    };
    env_logger::init_from_env(env_logger::Env::new().default_filter_or(state.config.log_level.clone()));
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .service(web::scope("/healthz").service(healthz))
            .service(
                web::scope(&state.config.prefix.clone())
                    .app_data(web::Data::new(state.clone()))
                    .service(avatar)
                    .service(hash),
            )
    })
    .bind((host, port))?
    .run()
    .await
}

#[get("")]
async fn healthz() -> impl Responder {
    "OK"
}

#[get("/hash/{hash}")]
async fn hash(path: web::Path<(String,)>) -> HttpResponse {
    let mail = path.into_inner().0;
    let sha256 = sha256(mail.as_str());
    let md5 = md5(mail.as_str());
    HttpResponse::Ok().body(format!("{mail} {sha256} {md5}"))
}

#[get("/{hash}")]
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
    log::debug!("serving {mail_hash}, size {size}");
    let mut path = build_path(
        vec![cache_dir.clone(), size.to_string(), mail_hash.clone()],
        Some(config.extension.clone()),
    );
    if !path.exists() || read_force_default(query) {
        log::debug!("not found {mail_hash}, size {size}, serving {default}");
        match default.as_str() {
            "404" => {
                return HttpResponse::NotFound().finish();
            }
            "mm" => {
                path = build_path(
                    vec![cache_dir.clone(), size.to_string(), "mm".to_string()],
                    Some(config.extension.clone()),
                );
            }
            _ => {
                path = build_path(
                    vec![cache_dir.clone(), size.to_string(), default.clone()],
                    Some(config.extension.clone()),
                );
            }
        }
    }
    let image_content = web::block(move || fs::read(path)).await.unwrap().unwrap();
    HttpResponse::build(StatusCode::OK)
        .content_type(format!("image/{}", config.extension))
        .body(image_content)
}

fn watch_directory(path: String, config: &Config, ldap: Option<Ldap>) {
    log::info!("watching {}", path);

    block_on(async {
        if let Err(e) = async_watch(path, config, ldap).await {
            log::error!("error: {:?}", e);
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

async fn async_watch<P: AsRef<Path>>(
    path: P,
    config: &Config,
    ldap: Option<Ldap>,
) -> notify::Result<()> {
    let (mut watcher, mut rx) = async_watcher()?;

    watcher.watch(path.as_ref(), RecursiveMode::Recursive)?;

    while let Some(res) = rx.next().await {
        match res {
            Ok(event) => match event.kind {
                notify::EventKind::Modify(ModifyKind::Name(RenameMode::Any)) => {
                    log::info!("a file was renamed");
                    if !path.as_ref().exists() {
                        evacuate_image(&event.paths[0], config, ldap.clone()).await;
                    } else {
                        process_image(&event.paths[0], config, ldap.clone(), false).await;
                    }
                }
                notify::EventKind::Create(_) => {
                    log::info!("found a new file");
                    process_image(&event.paths[0], config, ldap.clone(), false).await;
                }
                notify::EventKind::Modify(ModifyKind::Data(Content)) => {
                    log::info!("a file was updated");
                    update_image(&event.paths[0], config, ldap.clone()).await;
                }
                notify::EventKind::Remove(_) => {
                    log::info!("a file was removed");
                    evacuate_image(&event.paths[0], config, ldap.clone()).await;
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
    if let Some(extension) = get_extension(path) {
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

fn get_extension(path: &Path) -> Option<String> {
    let extension = path.extension();
    if let Some(extension) = extension {
        return Some(extension.to_str().unwrap().to_string());
    }
    None
}
