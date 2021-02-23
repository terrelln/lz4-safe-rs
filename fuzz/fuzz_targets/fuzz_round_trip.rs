#![no_main]
use libfuzzer_sys::fuzz_target;
use lz4::block;
use lz4_safe::decompress;

fuzz_target!(|data: &[u8]| {
    let mut compressed = block::compress(data, None, false).expect("LZ4 compression failed!");
    compressed.shrink_to_fit(); // Remove any extra bytes
    let mut decompressed = Vec::new();
    decompressed.resize(data.len(), 0);
    decompress(&mut decompressed, &compressed).expect("LZ4 decompression failed!");
    assert_eq!(data, decompressed);
});
