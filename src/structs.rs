use serde::Deserialize;

#[derive(Default, Clone, Debug)]
pub(crate) struct Config {
    pub host: String,
    pub port: u16,
    pub prefix: String,
    pub images: String,
    pub raw: String,
    pub extension: String,
    pub log_level: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ImageRequest {
    pub(crate) s: Option<u16>,
    pub(crate) size: Option<u16>,
    pub(crate) d: Option<String>,
    pub(crate) default: Option<String>,
    pub(crate) forcedefault: Option<char>,
    pub(crate) f: Option<char>,
}

#[derive(Clone)]
pub struct AppState {
    pub(crate) config: Config,
}