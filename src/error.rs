#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Generic {0}")]
    Generic(String),

    #[error("Static {0}")]
    Static(&'static str),

    #[error("transparent")]
    IO(#[from] std::io::Error),
}

pub type Result<T> = core::result::Result<T, Error>;
