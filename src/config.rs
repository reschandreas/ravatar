use crate::structs::{Config, ImageRequest, LdapConfig};
use actix_web::web::Query;
use std::env;

/**
 * Read the configuration from the environment variables
 */
pub(crate) fn read_config() -> Config {
    let prefix: String = env::var("PATH_PREFIX").unwrap_or("/avatar".into());
    let raw = env::var("RAW_PATH").unwrap_or("./raw".into());
    let images = env::var("IMAGES_PATH").unwrap_or("./images".into());
    let extension = env::var("EXTENSION").unwrap_or("png".into());
    let mm_extension = env::var("MM_EXTENSION").unwrap_or("png".into());
    let host = env::var("HOST").unwrap_or("0.0.0.0".into());
    let port: u16 = env::var("PORT").unwrap_or("8080".into()).parse().unwrap();
    let log_level = env::var("LOG_LEVEL").unwrap_or("info".into());
    let mut offer_original_dimensions: bool = env::var("OFFER_ORIGINAL_DIMENSIONS")
        .unwrap_or("false".into())
        .parse()
        .unwrap();
    let default_format = env::var("DEFAULT_FORMAT").unwrap_or("square".into());
    if default_format.eq("square") {
        log::info!("DEFAULT_FORMAT is set to square, this is the default behavior");
    } else if default_format.eq("original") {
        log::info!("DEFAULT_FORMAT is set to original, this will offer the original image per default, use original_dimensions=false to disable");
    } else {
        log::warn!("DEFAULT_FORMAT is set to an unknown value, defaulting to square");
    }
    if default_format.eq("original") {
        offer_original_dimensions = true;
    }
    let mut ldap: Option<LdapConfig> = None;
    if let Ok(ldap_url) = env::var("LDAP_URL") {
        let ldap_bind_username = env::var("LDAP_BIND_USERNAME").unwrap_or("".into());
        let ldap_bind_password = env::var("LDAP_BIND_PASSWORD").unwrap_or("".into());
        let ldap_base_dn = env::var("LDAP_BASE_DN").unwrap_or("".into());
        let ldap_search_filter = env::var("LDAP_SEARCH_FILTER").unwrap_or("".into());
        let ldap_input_attribute = env::var("LDAP_INPUT_ATTRIBUTE").unwrap_or("".into());
        let ldap_target_attributes = env::var("LDAP_TARGET_ATTRIBUTES")
            .unwrap_or("".into())
            .split(',')
            .map(|s| s.to_string())
            .collect();
        ldap = Some(LdapConfig {
            url: ldap_url,
            bind_username: ldap_bind_username,
            bind_password: ldap_bind_password,
            base_dn: ldap_base_dn,
            search_filter: ldap_search_filter,
            input_attribute: ldap_input_attribute,
            target_attributes: ldap_target_attributes,
        });
    } else {
        log::info!("LDAP_URL not set, LDAP authentication will not be available");
    }
    Config {
        host,
        port,
        prefix,
        images,
        raw,
        extension,
        mm_extension,
        default_original_dimensions: default_format.eq("original"),
        log_level,
        ldap,
        offer_original_dimensions,
    }
}

pub(crate) fn read_size(query: Query<ImageRequest>) -> u16 {
    if let Some(size_param) = query.s {
        return size_param;
    }
    if let Some(size_param) = query.size {
        return size_param;
    }
    80
}

pub(crate) fn read_default(query: Query<ImageRequest>) -> String {
    let mut default: String = "mm".to_string();
    if let Some(default_param) = &query.d {
        default.clone_from(default_param);
    }
    if let Some(default_param) = &query.default {
        default.clone_from(default_param);
    }
    if default.eq("mp") {
        default = "mm".to_string();
    }
    default
}

pub(crate) fn read_force_default(query: Query<ImageRequest>) -> bool {
    if let Some(force) = &query.f {
        return force.eq(&'y');
    }
    if let Some(force) = &query.forcedefault {
        return force.eq(&'y');
    }
    false
}
