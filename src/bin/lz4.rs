use std::fs::File;
use std::io::{Read,Write};
use std::env;
use std::os::raw::{c_int, c_char};
use std::time::Instant;

use lz4_safe::decompress;
use lz4_flex::decompress_into;
use lz4_sys::{LZ4_decompress_safe, LZ4_compress_default, LZ4_compressBound};
use lz4::block;
use lz_fear::raw::decompress_raw;

fn lz4_decompress(dst: &mut [u8], src: &[u8]) -> Result<usize, ()> {
    unsafe {
        let dst_ptr = dst.as_mut_ptr() as *mut c_char;
        let src_ptr = src.as_ptr() as *const c_char;
        let src_len = src.len() as c_int;
        let dst_len = dst.len() as c_int;
        let ret = LZ4_decompress_safe(src_ptr, dst_ptr, src_len, dst_len);
        if ret < 0 {
            Err(())
        } else {
            Ok(ret as usize)
        }
    }
}
fn lz4_compress(dst: &mut [u8], src: &[u8]) -> Result<usize, ()> {
    unsafe {
        let dst_ptr = dst.as_mut_ptr() as *mut c_char;
        let src_ptr = src.as_ptr() as *const c_char;
        let src_len = src.len() as c_int;
        let dst_len = dst.len() as c_int;
        let ret = LZ4_compress_default(src_ptr, dst_ptr, src_len, dst_len);
        if ret < 0 {
            Err(())
        } else {
            Ok(ret as usize)
        }
    }
}
fn lz4_compress_bound(len: usize) -> usize {
    unsafe {
        let c_len = len as c_int;
        let ret = LZ4_compressBound(c_len);
        ret as usize
    }
}

fn read_file(file: &str) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(file)?;

    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    Ok(data)
}

fn write_file(file: &str, data: &[u8]) -> std::io::Result<()> {
    let mut file = File::create(file)?;

    file.write_all(data)
}

// fn main() {
//     let args: Vec<String> = env::args().collect();
//     assert_eq!(args.len(), 3);
//     let data = read_file(&args[1]).expect("File read failed");
//     // let mut decompressed = block::decompress(&data, Some(10000000)).expect("lz4-block failed");
//     let mut decompressed = Vec::new();
//     decompressed.resize(std::cmp::max(10 * data.len(), 1 << 20), 0);
//     let dsize = lz4_decompress(&mut decompressed, &data).expect("Lz4 decompression failed");
//     // let dsize = decompress(&mut decompressed, &data).expect("Lz4 decompression failed");
//     decompressed.resize(dsize, 0);
//     // let mut time = None;
//     let start = Instant::now();
//     for _ in 0..100 {
//         if false {
//             decompress_into(&data, &mut decompressed).expect("Flex failed");
//         } else if false {
//             block::decompress(&data, Some(dsize as i32)).expect("lz4-block failed");
//         } else if false {
//             let _dsize = lz4_decompress(&mut decompressed, &data).expect("Lz4 decompression failed");
//         } else if false {
//             decompress_raw(&data, &[], &mut decompressed, dsize * 10).expect("lz-fear decompression failed");
//         } else {
//             let _dsize = decompress(&mut decompressed, &data).expect("Lz4 decompression failed");
//         }
//         // match time {
//         //     None => time = Some(stop - start),
//         //     Some(t) if stop - start < t => time = Some(stop - start),
//         //     _ => {}
//         // }
//     }
//     let stop = Instant::now();
//     let bytes = dsize * 100;
//     // let time = time.unwrap();
//     let time = stop - start;
//     println!("{} bytes processed in {:?} = {:.1} MB/s", bytes, time, (bytes as f64) / (time.as_micros() as f64));
//     write_file(&args[2], &decompressed).expect("File write failed");
// }

fn main() {
    let args: Vec<String> = env::args().collect();
    assert_eq!(args.len(), 2);
    let data = read_file(&args[1]).expect("File read failed");
    let mut compressed = Vec::new();
    compressed.resize(lz4_compress_bound(data.len()), 0);
    let csize = lz4_compress(&mut compressed, &data).expect("lz4 compress fail");
    compressed.resize(csize, 0);
    // let mut decompressed = block::decompress(&data, Some(10000000)).expect("lz4-block failed");
    let mut decompressed = Vec::new();
    decompressed.resize(data.len(), 0);
    let mut time = None;
    for _ in 0..100 {
        let start = Instant::now();
        if false {
            decompress_into(&compressed, &mut decompressed).expect("Flex failed");
        } else if false {
            block::decompress(&compressed, Some(data.len() as i32)).expect("lz4-block failed");
        } else if true {
            let _dsize = lz4_decompress(&mut decompressed, &compressed).expect("Lz4 decompression failed");
        } else if false {
            decompress_raw(&compressed, &[], &mut decompressed, data.len()).expect("lz-fear decompression failed");
        } else {
            let _dsize = decompress(&mut decompressed, &compressed).expect("Lz4 decompression failed");
        }
        let stop = Instant::now();
        match time {
            None => time = Some(stop - start),
            Some(t) if stop - start < t => time = Some(stop - start),
            _ => {}
        }
    }
    assert!(data == decompressed);
    let bytes = data.len();
    let time = time.unwrap();
    // let time = stop - start;
    println!("{} bytes processed in {:?} = {:.1} MB/s", bytes, time, (bytes as f64) / (time.as_micros() as f64));
}
