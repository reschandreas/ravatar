use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy)]
pub(crate) struct FaceLocation {
    pub(crate) top: u32,
    pub(crate) right: u32,
    pub(crate) bottom: u32,
    pub(crate) left: u32,
}

#[derive(Default, Clone, Deserialize, Debug, Copy)]
pub(crate) enum Format {
    #[default]
    Square,
    Original,
    Center,
    Portrait,
}

impl Format {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Format::Square => "square",
            Format::Original => "original",
            Format::Center => "center",
            Format::Portrait => "portrait",
        }
    }
}
#[derive(Default, Clone, Debug)]
pub(crate) struct Config {
    pub host: String,
    pub port: u16,
    pub prefix: String,
    pub images: String,
    pub raw: String,
    pub extension: String,
    pub mm_extension: String,
    pub default_format: Format,
    pub log_level: String,
    pub formats: Vec<Format>,
    pub ldap: Option<LdapConfig>,
    pub sizes: Vec<u32>,
    pub watch_directories: bool,
    pub scan_interval: u64,
}

#[derive(Default, Clone, Debug)]
pub(crate) struct LdapConfig {
    pub url: String,
    pub bind_username: String,
    pub bind_password: String,
    pub base_dn: String,
    pub search_filter: String,
    pub input_attribute: String,
    pub target_attributes: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct ImageRequest {
    pub(crate) s: Option<u16>,
    pub(crate) size: Option<u16>,
    pub(crate) d: Option<String>,
    pub(crate) default: Option<String>,
    pub(crate) force_default: Option<char>,
    pub(crate) f: Option<char>,
    pub(crate) format: Option<String>,
}

#[derive(Clone)]
pub struct AppState {
    pub(crate) config: Config,
}
