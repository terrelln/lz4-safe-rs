#[derive(PartialEq, Eq, Debug)]
pub enum Error {
    OffsetTooLarge,
    Truncation,
    OutputTooSmall,
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(std)]
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::OffsetTooLarge => write!(f, "LZ4 offset is too large! This is either corruption or the input was compressed with a different dictionary. Not retryable."),
            Error::Truncation => write!(f, "LZ4 source is truncated! This is either caused by corruption or a truncated LZ4 source. Not retryable."),
            Error::OutputTooSmall => write!(f, "Output buffer is too small! This is either caused by corruption, or the output buffer was too small. Retryable with a larger output buffer."),
        }
    }
}

#[cfg(std)]
impl std::error::Error for Error {}
