use std::fs::File;
use std::io::{Read,Write};
use std::env;
use std::os::raw::{c_int, c_char};

use lz4_safe::decompress;
use lz4_flex::decompress_into;
use lz4_sys::LZ4_decompress_safe;
use lz4::block;

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

fn main() {
    let args: Vec<String> = env::args().collect();
    assert_eq!(args.len(), 3);
    let data = read_file(&args[1]).expect("File read failed");
    // let mut decompressed = block::decompress(&data, Some(10000000)).expect("lz4-block failed");
    let mut decompressed = Vec::new();
    decompressed.resize(10 * data.len(), 0);
    let dsize = decompress(&mut decompressed, &data).expect("Lz4 decompression failed");
    decompressed.resize(dsize, 0);
    for _ in 0..100 {
        if false {
            decompress_into(&data, &mut decompressed).expect("Flex failed");
        } else if false {
        } else if false {
            block::decompress(&data, Some(dsize as i32)).expect("lz4-block failed");
        } else if false {
            let _dsize = lz4_decompress(&mut decompressed, &data).expect("Lz4 decompression failed");
        } else {
            let _dsize = decompress(&mut decompressed, &data).expect("Lz4 decompression failed");
        }
    }
    write_file(&args[2], &decompressed).expect("File write failed");

}
