use std::io;
use std::io::Read;

use ring::digest;

use hex;

const BLOCK_SIZE: usize = 1024;

fn main() {
    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf).expect("read stdin");
    let mut n = (buf.len() / BLOCK_SIZE) * BLOCK_SIZE;
    if n == buf.len() {
        n -= BLOCK_SIZE;
    }

    let mut hash = digest::digest(&digest::SHA256, &buf[n..buf.len()]);

    while n > 0 {
        buf[n..n + digest::SHA256.output_len].copy_from_slice(hash.as_ref());
        hash = digest::digest(
            &digest::SHA256,
            &buf[n - BLOCK_SIZE..n + digest::SHA256.output_len],
        );
        n -= BLOCK_SIZE;
    }
    assert!(n == 0);

    println!("{}", hex::encode(hash.as_ref()));
}
