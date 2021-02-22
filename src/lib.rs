#![feature(core_intrinsics)]
#![feature(test)]

mod decompress;
mod cursor;
mod copy;
mod error;

pub use decompress::decompress;
pub use error::Error;
pub use error::Result;
