#![no_std]

use core::ffi::c_void;

#[unsafe(no_mangle)]
pub static mut SDK_STATE: [u64; 16] = [0, 0, 0, 0x400a_0000_0000_0000, 0, 0xc01c_0000_0000_0000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

#[unsafe(no_mangle)]
pub static mut HOST_BSS: [u64; 1024] = [0; 1024];

#[unsafe(no_mangle)]
pub static HOST_READ_ONLY: [u64; 2] = [0x1234, 0x5678];

#[unsafe(no_mangle)]
pub static HOST_INTERIOR: &'static u64 = &HOST_READ_ONLY[1];

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcessId() -> u32;
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(instance: *mut c_void, reason: u32, reserved: *mut c_void) -> i32 {
    if reason == 1 {
        let state = core::ptr::addr_of_mut!(SDK_STATE).cast::<u64>();
        unsafe {
            state.add(11).write_volatile(instance as u64);
            state.add(12).write_volatile(u64::from(reason));
            state.add(13).write_volatile(reserved as u64);
            state.add(14).write_volatile(u64::from(GetCurrentProcessId()));
            state.add(15).write_volatile(state.add(15).read_volatile().wrapping_add(1));
        }
    }
    1
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { core::arch::asm!("int 0x29", in("ecx") 7u32, options(noreturn)); }
}
