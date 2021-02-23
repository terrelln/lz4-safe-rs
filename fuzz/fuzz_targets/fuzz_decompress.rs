#![no_main]
use std::convert::TryInto;
use libfuzzer_sys::fuzz_target;
use lz4_safe::decompress;

fuzz_target!(|data: &[u8]| {
    // Read a decompressed length
    let mut data = data;

    let len = if data.len() >= 4 {
        let len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        data = &data[4..];
        std::cmp::min(len, 1024 * 1024)
    } else if data.len() >= 1 {
        let len = data[0] as usize;
        data = &data[1..];
        len
    } else {
        0
    };

    let mut decompressed = Vec::new();
    decompressed.resize(len, 0);
    let _ = decompress(&mut decompressed, &data);
});
