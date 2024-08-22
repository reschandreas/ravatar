mod config;
mod image_processor;
mod ldap;
mod structs;
mod utils;

use std::fs;
use std::path::Path;

use crate::config::{read_config, read_default, read_force_default, read_size};
use crate::image_processor::{process_directory, resize_default, watch_directory};
use crate::structs::{AppState, Config, ImageRequest};
use crate::utils::{build_path, md5, sha256};
use actix_web::http::StatusCode;
use actix_web::middleware::Logger;
use actix_web::web::Query;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use ldap3::tokio;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = read_config();
    let host = config.host.clone();
    let port: u16 = config.port;
    let state = AppState { config };
    env_logger::init_from_env(
        env_logger::Env::new().default_filter_or(state.config.log_level.clone()),
    );
    let cloned_config = state.config.clone();
    tokio::spawn(async move {
        loop {
            log::info!("starting periodic check");
            let binding = cloned_config.raw.clone();
            let raw_path = Path::new(binding.as_str());
            resize_default(&cloned_config);
            process_directory(raw_path, &cloned_config).await;
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        }
    });
    let cloned_config = state.config.clone();
    tokio::spawn(async move {
        log::info!("starting watch");
        let raw_path = cloned_config.raw.clone();
        watch_directory(raw_path, &cloned_config.clone()).await;
    });
    println!("Starting server at http://{host}:{port}");
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default().exclude("/healthz"))
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
    .map(|_| {
        log::info!("shutting down");
    })
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
    let mut path_parts = vec![cache_dir.clone()];
    if query.original_dimensions.unwrap_or_default() {
        path_parts.push("original-dimensions".to_string());
    }
    path_parts.push(size.to_string());
    path_parts.push(mail_hash.clone());
    let mut path = build_path(path_parts, Some(config.extension.clone()));
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
