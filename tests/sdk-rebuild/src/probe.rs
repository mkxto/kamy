use crate::pe::Pe;
use anyhow::{Context, Result, ensure};
use std::ffi::c_void;
use std::path::Path;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryW(path: *const u16) -> *mut c_void;
    fn FreeLibrary(module: *mut c_void) -> i32;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn GetCurrentProcessId() -> u32;
    fn GetLastError() -> u32;
    fn VirtualAlloc(address: *mut c_void, size: usize, kind: u32, protection: u32) -> *mut c_void;
    fn VirtualFree(address: *mut c_void, size: usize, kind: u32) -> i32;
}

pub fn dll(path: &Path, variant: &str, unwind_ranges: &str) -> Result<()> {
    let pe = Pe::read(path)?;
    let wide: Vec<u16> = path
        .as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(Some(0))
        .collect();
    unsafe {
        let reservation = VirtualAlloc(
            pe.image_base as *mut c_void,
            pe.image_size as usize,
            0x2000,
            1,
        );
        ensure!(
            reservation as u64 == pe.image_base,
            "could not reserve exact preferred DLL image range to force ASLR: {}",
            GetLastError()
        );
        let image = LoadLibraryW(wide.as_ptr());
        ensure!(!image.is_null(), "LoadLibraryW failed: {}", GetLastError());
        ensure!(
            image as u64 != pe.image_base,
            "DLL did not relocate despite preferred-base reservation"
        );
        let state_pointer = GetProcAddress(image, c"SDK_STATE".as_ptr().cast()).cast::<[u64; 16]>();
        ensure!(!state_pointer.is_null(), "SDK_STATE export missing");
        let state = state_pointer.read_volatile();
        ensure!(
            state[0] == if variant == "baseline" { 0 } else { 12 },
            "DLL callback order oracle failed: trace={}",
            state[0]
        );
        ensure!(
            state[11] == image as u64
                && state[12] == 1
                && state[13] == 0
                && state[14] == u64::from(GetCurrentProcessId())
                && state[15] == 1,
            "original DLL entry did not observe exact native loader arguments"
        );
        if variant != "baseline" {
            ensure!(
                state[8..11] == state[11..14],
                "generated loader did not forward exact entry registers to callbacks and original entry"
            );
        }
        if variant == "abi" {
            ensure!(
                state[2..8]
                    == [
                        42,
                        0x400a_0000_0000_0000,
                        29,
                        0xc01c_0000_0000_0000,
                        86,
                        0x37bf
                    ],
                "authored dependency integer/floating/aggregate ABI oracle failed: {:?}",
                &state[2..8]
            );
        }
        if variant == "bounds" {
            ensure!(
                state[1] == 24,
                "DLL bounds MUST exclude the original entry: {}",
                state[1]
            );
        }
        let bss = GetProcAddress(image, c"HOST_BSS".as_ptr().cast()).cast::<u64>();
        ensure!(!bss.is_null(), "HOST_BSS export missing");
        ensure!(
            (0..1024).all(|index| bss.add(index).read_volatile() == 0),
            "mapped host BSS is not zero-filled"
        );
        if !unwind_ranges.is_empty() {
            crate::native::check_ranges(image.cast(), pe.image_size, unwind_ranges)?;
        }
        if variant == "ordered" {
            let entry: unsafe extern "system" fn(*mut c_void, u32, *mut c_void) -> i32 =
                core::mem::transmute(image.cast::<u8>().add(pe.entry as usize));
            let instance = image.cast::<u8>().add(0x123).cast::<c_void>();
            let reserved = 0x1020_3040usize as *mut c_void;
            let returned = entry(instance, 1, reserved);
            ensure!(
                returned == 1,
                "generated DLL loader changed original TRUE return to {returned}"
            );
            let state = state_pointer.read_volatile();
            ensure!(
                state[0] == 1212 && state[15] == 2,
                "explicit real DLL entry invocation did not execute callbacks exactly once in order"
            );
            ensure!(
                state[8..11] == [instance as u64, 1, reserved as u64]
                    && state[11..14] == state[8..11],
                "DLL entry forwarding lost non-null reserved or exact instance argument"
            );
            println!("dll_arguments=exact dll_return=TRUE trace=12 replay_trace=1212 aslr=1");
        } else {
            println!(
                "trace={} abi={} bounds={} aslr=1 host=dll",
                state[0],
                variant == "abi",
                state[1]
            );
        }
        ensure!(FreeLibrary(image) != 0, "FreeLibrary failed");
        ensure!(
            VirtualFree(reservation, 0, 0x8000) != 0,
            "preferred-base reservation release failed"
        );
    }
    Ok(())
}

pub fn dispatch(arguments: &[String]) -> Result<()> {
    ensure!(
        arguments.len() == 3,
        "probe-dll requires path, variant and source-qualified unwind probes"
    );
    dll(
        Path::new(arguments.first().context("missing DLL path")?),
        &arguments[1],
        &arguments[2],
    )
}
