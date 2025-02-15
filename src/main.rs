mod config;
mod image_processor;
mod ldap;
mod structs;
mod utils;

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::config::{read_config, read_default, read_force_default, read_size};
use crate::image_processor::{process_directory, resize_default, watch_directory};
use crate::structs::{AppState, Config, Format, ImageRequest};
use crate::utils::{build_path, md5, sha256};
use actix_web::http::StatusCode;
use actix_web::middleware::Logger;
use actix_web::{get, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
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
            log::debug!("starting periodic check");
            let binding = cloned_config.raw.clone();
            let raw_path = Path::new(binding.as_str());
            resize_default(&cloned_config);
            process_directory(raw_path, &cloned_config).await;
            tokio::time::sleep(tokio::time::Duration::from_secs(
                cloned_config.scan_interval * 60,
            ))
            .await;
        }
    });
    let cloned_config = state.config.clone();
    if cloned_config.watch_directories {
        tokio::spawn(async move {
            log::debug!("starting watch");
            let raw_path = cloned_config.raw.clone();
            watch_directory(raw_path, &cloned_config.clone()).await;
        });
    } else {
        log::debug!("not watching directories, as WATCHING_DIRECTORIES is false");
    }
    log::info!("Starting server at http://{host}:{port}");
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
    req: HttpRequest,
) -> HttpResponse {
    let query_string = req.query_string();
    let parsed_query: HashMap<String, String> =
        url::form_urlencoded::parse(query_string.as_bytes())
            .into_owned()
            .collect::<Vec<_>>()
            .into_iter()
            .map(|(k, v)| (k, v.to_string()))
            .collect();
    let query = ImageRequest {
        s: parsed_query.get("s").and_then(|s| s.parse::<u16>().ok()),
        size: parsed_query.get("size").and_then(|s| s.parse::<u16>().ok()),
        d: parsed_query.get("d").cloned(),
        default: parsed_query.get("default").cloned(),
        force_default: parsed_query
            .get("forcedefault")
            .and_then(|f| f.chars().next()),
        f: parsed_query.get("f").and_then(|f| f.chars().next()),
        format: parsed_query.get("format").cloned(),
    };
    let mail_hash = path.into_inner().0;
    let config: Config = data.config.clone();
    let cache_dir = config.images;
    let size: u16 = read_size(query.clone());
    let default: String = read_default(query.clone());
    log::debug!("serving {mail_hash}, size {size}");
    let mut path_parts = vec![cache_dir.clone()];
    let default_format = config.default_format;
    let mut format_to_serve = match query.format.clone() {
        None => default_format,
        Some(value) => match value.as_str() {
            "square" => Format::Square,
            "original" => Format::Original,
            "center" => Format::Center,
            _ => config.default_format,
        },
    };
    if !config.formats.contains(&format_to_serve) {
        log::warn!(
            "format {format} is not supported, falling back to default",
            format = format_to_serve.as_str()
        );
        format_to_serve = default_format;
    }
    path_parts.push(format_to_serve.as_str().to_string());

    path_parts.push(size.to_string());
    path_parts.push(mail_hash.clone());

    let mut path = build_path(path_parts, Some(config.extension.clone()));
    if !path.exists() || read_force_default(query) {
        log::info!("could not find {mail_hash}, size {size}, serving {default}");
        match default.as_str() {
            "404" => {
                return HttpResponse::NotFound().finish();
            }
            "mm" => {
                path = build_path(
                    vec![
                        cache_dir.clone(),
                        format_to_serve.as_str().to_string(),
                        size.to_string(),
                        "mm".to_string(),
                    ],
                    Some(config.extension.clone()),
                );
            }
            _ => {
                path = build_path(
                    vec![
                        cache_dir.clone(),
                        format_to_serve.as_str().to_string(),
                        default.clone(),
                    ],
                    Some(config.extension.clone()),
                );
            }
        }
    }
    if let Ok(image_content) = web::block(move || fs::read(path)).await {
        match image_content {
            Ok(content) => HttpResponse::build(StatusCode::OK)
                .content_type(format!("image/{}", config.extension))
                .body(content),
            Err(_) => HttpResponse::NotFound().finish(),
        }
    } else {
        HttpResponse::NotFound().finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};

    #[actix_web::test]
    async fn test_healthz_get() {
        let app =
            test::init_service(App::new().service(web::scope("/healthz").service(healthz))).await;
        let req = test::TestRequest::get().uri("/healthz").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
        let content = test::read_body(resp).await;
        assert_eq!(content, "OK");
    }

    #[actix_web::test]
    async fn test_hash_get() {
        let state = AppState {
            config: Config {
                host: String::from("localhost"),
                port: 8080,
                prefix: "".to_string(),
                images: "images".to_string(),
                raw: "raw".to_string(),
                extension: "png".to_string(),
                mm_extension: "png".to_string(),
                default_format: Format::Square,
                log_level: "info".to_string(),
                ldap: None,
                formats: Vec::from([Format::Square, Format::Center, Format::Original]),
                sizes: vec![16, 24, 32, 48, 64, 80, 96, 128, 256, 512, 1024],
                scan_interval: 10,
                watch_directories: false,
            },
        };
        let app = test::init_service(
            App::new().service(
                web::scope(&state.config.prefix.clone())
                    .app_data(web::Data::new(state.clone()))
                    .service(hash),
            ),
        )
        .await;
        let req = test::TestRequest::get().uri("/hash/input").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
        let content = test::read_body(resp).await;
        assert_eq!(content, "input c96c6d5be8d08a12e7b5cdc1b207fa6b2430974c86803d8891675e76fd992c20 a43c1b0aa53a0c908810c06ab1ff3967");
    }
}
