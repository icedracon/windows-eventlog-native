use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Win32 error: {code:#010x} ({context})")]
    Win32 { code: u32, context: &'static str },

    #[error("XML parse error: {0}")]
    Xml(String),

    #[error("invalid UTF-16 in rendered event")]
    Utf16,

    #[error("unsupported platform (only cfg(windows) is implemented)")]
    UnsupportedPlatform,

    #[error("channel {0:?} inaccessible: {1}")]
    ChannelAccess(String, String),

    #[error("timestamp conversion failed: FILETIME={0}")]
    BadFileTime(u64),

    #[error("other: {0}")]
    Other(String),
}

impl From<quick_xml::Error> for Error {
    fn from(e: quick_xml::Error) -> Self {
        Error::Xml(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
