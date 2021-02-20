use std::convert::TryInto;

use aes::cipher::generic_array::{typenum::Unsigned, GenericArray};
use aes::cipher::{BlockCipher, NewBlockCipher};
use aes::Aes128;
use hex;

fn main() {
    let mut plaintext = [0u8; 1024];

    let cbc_key = hex::decode("140b41b22a29beb4061bda66b6747e14")
        .expect("could not decode key from hex string");
    let cbc_ciphertext1 = hex::decode("4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81").expect("could not decode ciphertext from hex string");
    let cbc_ciphertext2 = hex::decode("5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253").expect("could not decode ciphertext from hex string");
    let n = cbc_decrypt(&cbc_key, &cbc_ciphertext1, &mut plaintext);
    println!("{}", std::str::from_utf8(&plaintext[..n]).unwrap());
    let n = cbc_decrypt(&cbc_key, &cbc_ciphertext2, &mut plaintext);
    println!("{}", std::str::from_utf8(&plaintext[..n]).unwrap());

    let ctr_key = hex::decode("36f18357be4dbd77f050515c73fcf9f2")
        .expect("could not decode key from hex string");
    let ctr_ciphertext1 = hex::decode("69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329").expect("could not decode ciphertext from hex string");
    let ctr_ciphertext2 = hex::decode("770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451").expect("could not decode ciphertext from hex string");
    let n = ctr_decrypt(&ctr_key, &ctr_ciphertext1, &mut plaintext);
    println!("{}", std::str::from_utf8(&plaintext[..n]).unwrap());
    let n = ctr_decrypt(&ctr_key, &ctr_ciphertext2, &mut plaintext);
    println!("{}", std::str::from_utf8(&plaintext[..n]).unwrap());
}

fn cbc_decrypt(key: &[u8], ciphertext: &[u8], plaintext: &mut [u8]) -> usize {
    let key = GenericArray::from_slice(key);

    let cipher = Aes128::new(&key);
    let bs = <Aes128 as BlockCipher>::BlockSize::to_usize();

    let mut i = bs;
    while i + bs <= ciphertext.len() && i <= plaintext.len() {
        let mut block = GenericArray::clone_from_slice(&ciphertext[i..i + bs]);
        cipher.decrypt_block(&mut block);

        xor(
            block.as_slice(),
            &ciphertext[i - bs..i],
            &mut plaintext[i - bs..i],
        );
        i += bs;
    }

    i -= bs;
    let pad_num = plaintext[i - 1] as usize;

    i - pad_num
}

fn ctr_decrypt(key: &[u8], ciphertext: &[u8], plaintext: &mut [u8]) -> usize {
    let key = GenericArray::from_slice(key);

    let cipher = Aes128::new(&key);
    let bs = <Aes128 as BlockCipher>::BlockSize::to_usize();

    let mut iv = u128::from_be_bytes(ciphertext[..bs].try_into().unwrap());

    let mut i = 0;
    while bs + i < ciphertext.len() && i + bs <= plaintext.len() {
        let x = iv.to_be_bytes();
        let mut block = GenericArray::clone_from_slice(&x);
        cipher.encrypt_block(&mut block);

        let n = xor(
            block.as_slice(),
            &ciphertext[bs + i..min(bs + i + bs, ciphertext.len())],
            &mut plaintext[i..i + bs],
        );
        i += n;
        iv += 1;
    }

    i
}

fn xor(a: &[u8], b: &[u8], c: &mut [u8]) -> usize {
    let min_len = min(a.len(), min(b.len(), c.len()));
    for i in 0..min_len {
        c[i] = a[i] ^ b[i];
    }
    min_len
}

fn min(a: usize, b: usize) -> usize {
    if a > b {
        b
    } else {
        a
    }
}
