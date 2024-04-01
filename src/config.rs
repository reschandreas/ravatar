#[derive(Default, Clone, Debug)]
pub(crate) struct Config {
    pub port: u16,
    pub prefix: String,
    pub images: String,
    pub raw: String,
}
