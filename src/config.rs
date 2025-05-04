use crate::structs::{Config, Format, ImageRequest, LdapConfig};
use std::cmp::PartialEq;
use std::env;
use crate::io::LocalStorage;

impl PartialEq for Format {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

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
    let scan_interval = env::var("SCAN_INTERVAL").unwrap_or("60".into()).parse().unwrap();
    let storage_account_url = env::var("STORAGE_ACCOUNT_URL").ok();
    let watch_directories: bool = env::var("WATCH_DIRECTORIES")
        .unwrap_or("true".into())
        .parse()
        .unwrap() && storage_account_url.is_none();
    
    let mut formats: Vec<Format> = vec![Format::Square];
    let offer_original_dimensions: bool = env::var("OFFER_ORIGINAL_DIMENSIONS")
        .unwrap_or("false".into())
        .parse()
        .unwrap();
    let offer_centered: bool = env::var("OFFER_FACE_CENTERED_IMAGE")
        .unwrap_or("false".into())
        .parse()
        .unwrap();
    let offer_portrait: bool = env::var("OFFER_PORTRAIT_IMAGE")
        .unwrap_or("true".into())
        .parse()
        .unwrap();
    let default_format: Format = match env::var("DEFAULT_FORMAT")
        .unwrap_or("square".into())
        .as_str()
    {
        "square" => Format::Square,
        "original" => Format::Original,
        "center" => Format::Center,
        "portrait" => Format::Portrait,
        _ => Format::Square,
    };
    if offer_centered || default_format == Format::Center {
        formats.push(Format::Center);
    }
    if offer_portrait || default_format == Format::Portrait {
        formats.push(Format::Portrait);
    }
    if offer_original_dimensions || default_format == Format::Original {
        formats.push(Format::Original);
    }

    if default_format == Format::Square {
        log::info!("DEFAULT_FORMAT is set to square, this is the default behavior");
    } else if default_format == Format::Original {
        log::info!("DEFAULT_FORMAT is set to original, this will offer the original image per default, use format=square to disable");
        formats.push(Format::Original);
    }
    if default_format == Format::Center {
        log::info!("DEFAULT_FORMAT is set to center, this will detect the face and center it in the image, if the image is not squared already");
    } else {
        log::warn!("DEFAULT_FORMAT is set to an unknown value, defaulting to square");
    }
    let mut ldap: Option<LdapConfig> = None;
    if let Ok(ldap_url) = env::var("LDAP_URL") {
        let ldap_bind_username = env::var("LDAP_BIND_USERNAME").unwrap_or_default();
        let ldap_bind_password = env::var("LDAP_BIND_PASSWORD").unwrap_or_default();
        let ldap_base_dn = env::var("LDAP_BASE_DN").unwrap_or_default();
        let ldap_search_filter = env::var("LDAP_SEARCH_FILTER").unwrap_or_default();
        let ldap_input_attribute = env::var("LDAP_INPUT_ATTRIBUTE").unwrap_or_default();
        let ldap_target_attributes = env::var("LDAP_TARGET_ATTRIBUTES")
            .unwrap_or_default()
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
        default_format,
        log_level,
        ldap,
        formats,
        sizes: vec![16, 24, 32, 48, 64, 80, 96, 128, 256, 512, 1024],
        watch_directories,
        scan_interval,
        storage_account_url,
        storage_backend: Some(LocalStorage::default()),
    }
}

pub(crate) fn read_size(query: ImageRequest) -> u16 {
    if let Some(size_param) = query.s {
        return size_param;
    }
    if let Some(size_param) = query.size {
        return size_param;
    }
    80
}

pub(crate) fn read_default(query: ImageRequest) -> String {
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

pub(crate) fn read_force_default(query: ImageRequest) -> bool {
    if let Some(force) = &query.f {
        return force.eq(&'y');
    }
    if let Some(force) = &query.force_default {
        return force.eq(&'y');
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_read_size() {
        let query = ImageRequest {
            s: Some(64),
            size: None,
            d: None,
            default: None,
            f: None,
            force_default: None,
            format: None,
        };
        assert_eq!(read_size(query), 64);
        let query = ImageRequest {
            s: None,
            size: Some(32),
            d: None,
            default: None,
            f: None,
            force_default: None,
            format: None,
        };
        assert_eq!(read_size(query), 32);
    }

    #[test]
    fn test_read_default() {
        let query = ImageRequest {
            s: None,
            size: None,
            d: Some("mp".to_string()),
            default: None,
            f: None,
            force_default: None,
            format: None,
        };
        assert_eq!(read_default(query), "mm");
        let query = ImageRequest {
            s: None,
            size: None,
            d: None,
            default: Some("mp".to_string()),
            f: None,
            force_default: None,
            format: None,
        };
        assert_eq!(read_default(query), "mm");
    }

    #[test]
    fn test_read_force_default() {
        let query = ImageRequest {
            s: None,
            size: None,
            d: None,
            default: None,
            f: Some('y'),
            force_default: None,
            format: None,
        };
        assert_eq!(read_force_default(query), true);
        let query = ImageRequest {
            s: None,
            size: None,
            d: None,
            default: None,
            f: None,
            force_default: Some('y'),
            format: None,
        };
        assert_eq!(read_force_default(query), true);
    }

    #[test]
    fn test_read_config() {
        env::set_var("PATH_PREFIX", "prefix");
        env::set_var("RAW_PATH", "raw-path");
        env::set_var("IMAGES_PATH", "images");
        env::set_var("EXTENSION", "heic");
        env::set_var("MM_EXTENSION", "heic");
        env::set_var("HOST", "remotehost");
        env::set_var("PORT", "8081");
        env::set_var("LOG_LEVEL", "some");
        env::set_var("OFFER_ORIGINAL_DIMENSIONS", "true");
        env::set_var("OFFER_FACE_CENTERED_IMAGE", "true");
        env::set_var("OFFER_PORTRAIT_IMAGE", "true");
        env::set_var("DEFAULT_FORMAT", "portrait");
        env::set_var("WATCH_DIRECTORIES", "false");
        env::set_var("SCAN_INTERVAL", "10");
        env::set_var("LDAP_URL", "ldap://localhost:389");
        env::set_var("LDAP_BIND_USERNAME", "cn=admin,dc=example,dc=com");
        env::set_var("LDAP_BIND_PASSWORD", "admin");
        env::set_var("LDAP_BASE_DN", "dc=example,dc=com");
        env::set_var("LDAP_SEARCH_FILTER", "(&(objectClass=inetOrgPerson)(uid=%s))");
        env::set_var("LDAP_INPUT_ATTRIBUTE", "uid");
        env::set_var("LDAP_TARGET_ATTRIBUTES", "cn,mail");
        let config = read_config();
        assert_eq!(config.host, "remotehost");
        assert_eq!(config.port, 8081);
        assert_eq!(config.prefix, "prefix");
        assert_eq!(config.images, "images");
        assert_eq!(config.raw, "raw-path");
        assert_eq!(config.formats, vec![Format::Square, Format::Center, Format::Portrait, Format::Original]);
        assert_eq!(config.extension, "heic");
        assert_eq!(config.mm_extension, "heic");
        assert_eq!(config.default_format, Format::Portrait);
        assert_eq!(config.log_level, "some");
        assert_eq!(config.scan_interval, 10);
        assert_eq!(config.watch_directories, false);
        assert_eq!(config.ldap.is_some(), true);
        let ldap = config.ldap.unwrap();
        assert_eq!(ldap.url, "ldap://localhost:389");
        assert_eq!(ldap.bind_username, "cn=admin,dc=example,dc=com");
        assert_eq!(ldap.bind_password, "admin");
        assert_eq!(ldap.base_dn, "dc=example,dc=com");
        assert_eq!(ldap.search_filter, "(&(objectClass=inetOrgPerson)(uid=%s))");
        assert_eq!(ldap.input_attribute, "uid");
        assert_eq!(ldap.target_attributes, vec!["cn".to_string(), "mail".to_string()]);
    }
}
