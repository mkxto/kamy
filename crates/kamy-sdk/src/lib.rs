#![no_std]

use core::ffi::c_void;

/// Receives the original Win64 entry registers, not argc/argv/envp.
/// Zero continues startup; any other status terminates with fast-fail.
pub type Entry = unsafe extern "system" fn(*mut c_void, *mut c_void, *mut c_void) -> i32;

pub const SUCCESS: i32 = 0;

/// Exports a Win64 callback and the freestanding module's aborting panic handler.
#[macro_export]
macro_rules! plugin {
    ($initialize:path) => {
        $crate::plugin!(kamy_plugin_init, $initialize);
    };
    ($name:ident, $initialize:path) => {
        #[unsafe(no_mangle)]
        #[doc = "# Safety\nArguments MUST be the original target's Win64 entry arguments."]
        pub unsafe extern "system" fn $name(
            a1: *mut core::ffi::c_void,
            a2: *mut core::ffi::c_void,
            a3: *mut core::ffi::c_void,
        ) -> i32 {
            let initialize: $crate::Entry = $initialize;
            unsafe { initialize(a1, a2, a3) }
        }

        #[panic_handler]
        fn __kamy_panic(_: &core::panic::PanicInfo<'_>) -> ! {
            unsafe { core::arch::asm!("int 0x29", in("ecx") 7u32, options(noreturn)); }
        }
    };
}

/// Declares linker-filled bounds over the ordered startup callback table.
#[macro_export]
macro_rules! declare_init_table {
    () => {
        #[unsafe(no_mangle)]
        #[used]
        pub static mut SYMBOL_init_table_start: *const core::ffi::c_void = core::ptr::null();
        #[unsafe(no_mangle)]
        #[used]
        pub static mut SYMBOL_init_table_end: *const core::ffi::c_void = core::ptr::null();
    };
}
