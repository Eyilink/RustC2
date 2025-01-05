use aes::{Aes128, BlockEncrypt, BlockDecrypt};
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use std::str;
use std::io::{Read, Write};
use std::net::TcpStream;


type Aes128Cbc = Cbc<Aes128, Pkcs7>;

fn xor_encrypt_decrypt(data: &mut Vec<u8>, key: u8) {
    for byte in data.iter_mut() {
        *byte ^= key;
    }
}

fn main() {
    let key = b"verysecretkey123"; // 16 bytes
    let iv = b"randomiv12345678"; // 16 bytes
    let cipher = Aes128Cbc::new_from_slices(key, iv).unwrap();

    let mut data = b"run command".to_vec();
    let xkey = 123;
    xor_encrypt_decrypt(&mut data,xkey );
    let encrypted_data = cipher.encrypt_vec(&data);

    let mut stream = TcpStream::connect("127.0.0.1:8080").unwrap();
    stream.write(&encrypted_data).unwrap();
    let mut buffer = [0; 512];
    stream.read(&mut buffer).unwrap();
    println!("Response: {:?}", buffer);
    
}
