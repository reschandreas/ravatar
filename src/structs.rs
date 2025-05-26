use crate::io::StorageBackendType;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
    pub storage_backend: Option<StorageBackendType>,
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

pub struct ResizableImage {
    pub(crate) source: PathBuf,
    pub(crate) destination: PathBuf,
    pub(crate) size: u32,
    pub(crate) alternate_names: Vec<String>,
    pub(crate) face_location: Option<FaceLocation>,
}


// used for list blobs
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EnumerationResults {
    #[serde(rename = "@ServiceEndpoint")]
    service_endpoint: String,
    #[serde(rename = "@ContainerName")]
    container_name: String,
    prefix: Option<String>,
    pub(crate) blobs: Option<Blobs>,
    next_marker: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Blobs {
    #[serde(rename = "Blob")]
    pub(crate) blob: Option<Vec<Blob>>,
}

#[derive(Debug, Deserialize)]
pub struct Blob {
    #[serde(rename = "Name")]
    pub(crate) name: String,
    #[serde(rename = "Properties")]
    properties: Properties,
    #[serde(rename = "OrMetadata")]
    or_metadata: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Properties {
    #[serde(rename = "Creation-Time")]
    creation_time: Option<String>,
    #[serde(rename = "Last-Modified")]
    last_modified: Option<String>,
    etag: Option<String>,
    #[serde(rename = "Content-Length")]
    content_length: Option<u64>,
    #[serde(rename = "Content-Type")]
    content_type: Option<String>,
    #[serde(rename = "Content-Encoding")]
    content_encoding: Option<String>,
    #[serde(rename = "Content-Language")]
    content_language: Option<String>,
    #[serde(rename = "Content-CRC64")]
    content_crc64: Option<String>,
    #[serde(rename = "Content-MD5")]
    content_md5: Option<String>,
    #[serde(rename = "Cache-Control")]
    cache_control: Option<String>,
    #[serde(rename = "Content-Disposition")]
    content_disposition: Option<String>,
    #[serde(rename = "BlobType")]
    blob_type: Option<String>,
    #[serde(rename = "AccessTier")]
    access_tier: Option<String>,
    #[serde(rename = "AccessTierInferred")]
    access_tier_inferred: Option<bool>,
    #[serde(rename = "LeaseStatus")]
    lease_status: Option<String>,
    #[serde(rename = "LeaseState")]
    lease_state: Option<String>,
    #[serde(rename = "ServerEncrypted")]
    server_encrypted: Option<bool>,
}