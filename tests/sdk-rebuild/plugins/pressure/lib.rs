#![no_std]
use core::ffi::c_void;
unsafe extern "system" { static __ImageBase: u8; }
kamy_sdk::declare_init_table!();
const fn coordinate(value: &str) -> usize {
    let bytes = value.as_bytes();
    let mut result = 0;
    let mut index = 0;
    while index < bytes.len() {
        result = result * 10 + (bytes[index] - b'0') as usize;
        index += 1;
    }
    result
}
unsafe extern "system" fn initialize(_: *mut c_void, _: *mut c_void, _: *mut c_void) -> i32 {
    let begin = unsafe { core::ptr::addr_of!(SYMBOL_init_table_start).read_volatile() } as usize;
    let end = unsafe { core::ptr::addr_of!(SYMBOL_init_table_end).read_volatile() } as usize;
    if begin == 0 || end.wrapping_sub(begin) != 24 { return 23; }
    let base = core::ptr::addr_of!(__ImageBase) as usize;
    let trace = (base + coordinate(env!("SDK_TRACE_RVA"))) as *mut u64;
    let previous = unsafe { trace.read_volatile() };
    unsafe { trace.write_volatile(previous.wrapping_mul(10).wrapping_add(1)); }
    kamy_sdk::SUCCESS
}
kamy_sdk::plugin!(initialize);
