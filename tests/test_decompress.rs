extern crate quickcheck;
#[macro_use(quickcheck)]
extern crate quickcheck_macros;
extern crate lz4;

use lz4::block;
use lz4_safe::decompress;

#[quickcheck]
fn quickcheck_lz4_round_trip(data: Vec<u8>) -> bool {
    let compressed = block::compress(&data, None, false).expect("LZ4 compression failed!");
    let mut decompressed = Vec::new();
    decompressed.resize(data.len(), 0);
    decompress(&mut decompressed, &compressed).expect("LZ4 decompression failed!");
    data == decompressed
}

#[quickcheck]
fn quickcheck_lz4_decompress_doesnt_panic(data: Vec<u8>, len: usize) -> bool {
    let mut decompressed = Vec::new();
    decompressed.resize(std::cmp::min(len, 1 << 16), 0);
    let _ = decompress(&mut decompressed, &data);
    true
}
