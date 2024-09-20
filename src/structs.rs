use serde::Deserialize;

#[derive(Default, Clone, Debug)]
pub(crate) struct Config {
    pub host: String,
    pub port: u16,
    pub prefix: String,
    pub images: String,
    pub raw: String,
    pub extension: String,
    pub mm_extension: String,
    pub log_level: String,
    pub offer_original_dimensions: bool,
    pub ldap: Option<LdapConfig>,
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

#[derive(Debug, Deserialize, Clone)]
pub struct ImageRequest {
    pub(crate) s: Option<u16>,
    pub(crate) size: Option<u16>,
    pub(crate) d: Option<String>,
    pub(crate) default: Option<String>,
    pub(crate) forcedefault: Option<char>,
    pub(crate) f: Option<char>,
    pub(crate) original_dimensions: Option<bool>,
}

#[derive(Clone)]
pub struct AppState {
    pub(crate) config: Config,
}
