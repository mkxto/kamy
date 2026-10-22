#![no_std]

use core::ffi::c_void;

unsafe extern "system" {
    static __ImageBase: u8;
}

kamy_sdk::declare_init_table!();

const fn decimal(value: &str) -> usize {
    let bytes = value.as_bytes();
    let mut result = 0;
    let mut index = 0;
    while index < bytes.len() {
        result = result * 10 + (bytes[index] - b'0') as usize;
        index += 1;
    }
    result
}

const TRACE_RVA: usize = decimal(env!("SDK_TRACE_RVA"));
const TABLE_BYTES: usize = decimal(env!("SDK_TABLE_BYTES"));

#[cfg(feature = "abi")]
#[unsafe(no_mangle)]
pub static SDK_READ_ONLY: [u64; 4] = [23, 22, 17, 31];

#[cfg(feature = "abi")]
#[unsafe(no_mangle)]
pub static SDK_INTERIOR: &'static u64 = &SDK_READ_ONLY[1];

#[cfg(feature = "abi")]
#[unsafe(no_mangle)]
pub static mut SDK_MODULE_BSS: [u64; 1024] = [0; 1024];

unsafe extern "system" fn initialize(a1: *mut c_void, a2: *mut c_void, a3: *mut c_void) -> i32 {
    let state = (core::ptr::addr_of!(__ImageBase) as usize + TRACE_RVA) as *mut u64;
    #[cfg(feature = "first")]
    unsafe {
        let previous = state.read_volatile();
        state.write_volatile(previous.wrapping_mul(10).wrapping_add(1));
        state.add(8).write_volatile(a1 as u64);
        state.add(9).write_volatile(a2 as u64);
        state.add(10).write_volatile(a3 as u64);
    }
    #[cfg(feature = "second")]
    unsafe {
        let previous = state.read_volatile();
        state.write_volatile(previous.wrapping_mul(10).wrapping_add(2));
    }
    #[cfg(feature = "bounds")]
    unsafe {
        let begin = core::ptr::addr_of!(SYMBOL_init_table_start).read_volatile() as usize;
        let end = core::ptr::addr_of!(SYMBOL_init_table_end).read_volatile() as usize;
        if begin == 0 || end.wrapping_sub(begin) != TABLE_BYTES {
            return 23;
        }
        state.add(1).write_volatile(end.wrapping_sub(begin) as u64);
    }
    #[cfg(feature = "abi")]
    unsafe {
        let bss = core::ptr::addr_of_mut!(SDK_MODULE_BSS).cast::<u64>();
        if state.add(7).read_volatile() == 0 && (bss.read_volatile() != 0 || bss.add(1023).read_volatile() != 0) {
            return 41;
        }
        bss.write_volatile(0x1357);
        bss.add(1023).write_volatile(0x2468);
        let read_only = core::ptr::addr_of!(SDK_READ_ONLY).cast::<u64>();
        let integer = sdk_rebuild_dependency::integer(read_only.read_volatile());
        let floating = sdk_rebuild_dependency::floating(f64::from_bits(state.add(3).read_volatile()));
        let interior = core::ptr::addr_of!(SDK_INTERIOR).read_volatile();
        let mixed = sdk_rebuild_dependency::mixed((core::ptr::read_volatile(interior), f64::from_bits(state.add(5).read_volatile())));
        let aggregate = sdk_rebuild_dependency::aggregate([read_only.add(2).read_volatile(), read_only.read_volatile(), read_only.add(3).read_volatile()]);
        state.add(2).write_volatile(integer);
        state.add(3).write_volatile(floating.to_bits());
        state.add(4).write_volatile(mixed.0);
        state.add(5).write_volatile(mixed.1.to_bits());
        state.add(6).write_volatile(aggregate[0].wrapping_add(aggregate[1]).wrapping_add(aggregate[2]));
        state.add(7).write_volatile(bss.read_volatile().wrapping_add(bss.add(1023).read_volatile()));
    }
    let _ = (state, a1, a2, a3, TABLE_BYTES);
    #[cfg(feature = "fastfail")]
    {
        37
    }
    #[cfg(not(feature = "fastfail"))]
    {
        kamy_sdk::SUCCESS
    }
}

kamy_sdk::plugin!(initialize);
