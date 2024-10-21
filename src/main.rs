use std::char::{decode_utf16, REPLACEMENT_CHARACTER};
use std::slice;
use windows::core::PCWSTR;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::Memory::{CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, FILE_MAP_READ, MEMORY_MAPPED_VIEW_ADDRESS, PAGE_READWRITE};

fn main() {
    const SZ_NAME: &str = "TrainCrewOutput\0";
    let sz_name_wide: Vec<u16> = SZ_NAME.encode_utf16().collect();
    unsafe {
        let handle = CreateFileMappingW(
            HANDLE(std::ptr::null_mut()),
            Some(std::ptr::null_mut() as *const SECURITY_ATTRIBUTES),
            PAGE_READWRITE,
            0, 8192, PCWSTR(sz_name_wide.as_ptr()))
            .unwrap();
        let buf: MEMORY_MAPPED_VIEW_ADDRESS = MapViewOfFile(
                handle, FILE_MAP_READ, 0, 0, 2048);
        loop {
            let size =slice::from_raw_parts(buf.Value as *const u8, 4).try_into().map(i32::from_le_bytes);
            let raw_data = size.map(
                |size| slice::from_raw_parts(buf.Value.offset(4) as *const u16, size as usize)
            );
            let data = raw_data
                .map(|data| decode_utf16(data.iter().cloned())
                    .map(|r| r.unwrap_or(REPLACEMENT_CHARACTER))
                    .collect::<String>());
            match data { 
                Ok(data) => print!("{}", data),
                Err(why) => eprintln!("Error: {}", why),
            }
        }
        UnmapViewOfFile(buf).ok();
    }
}