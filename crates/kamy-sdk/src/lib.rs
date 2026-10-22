#![no_std]

use core::ffi::c_void;

/// Receives the original Win64 entry registers, not argc/argv/envp.
/// Zero continues startup; any other status terminates with fast-fail.
pub type Entry = unsafe extern "system" fn(*mut c_void, *mut c_void, *mut c_void) -> i32;

pub const SUCCESS: i32 = 0;

/// Exports a Win64 callback and supplies the freestanding module's runtime.
///
/// Owns the aborting panic handler and MSVC floating-point marker. Modules MUST NOT
/// also link a CRT or another runtime defining those symbols.
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

        // LLVM adds the marker reference after IR optimization, so retain its data definition.
        // https://github.com/llvm/llvm-project/blob/release/22.x/llvm/lib/Target/X86/X86AsmPrinter.cpp
        #[cfg(all(target_os = "windows", target_env = "msvc", target_arch = "x86_64"))]
        #[unsafe(export_name = "_fltused")]
        #[used]
        static mut __KAMY_FLTUSED: i32 = 0x9875;

        #[panic_handler]
        fn __kamy_panic(_: &core::panic::PanicInfo<'_>) -> ! {
            unsafe { core::arch::asm!("int 0x29", in("ecx") 7u32, options(noreturn)); }
        }
    };
}

/// Declares linker-filled bounds over the ordered startup callback table.
/// The null cells use initialized storage because the final linker fills them before loading.
#[macro_export]
macro_rules! declare_init_table {
    () => {
        #[unsafe(no_mangle)]
        #[unsafe(link_section = ".data$kamy_init_table_start")]
        #[used]
        pub static mut SYMBOL_init_table_start: *const core::ffi::c_void = core::ptr::null();
        #[unsafe(no_mangle)]
        #[unsafe(link_section = ".data$kamy_init_table_end")]
        #[used]
        pub static mut SYMBOL_init_table_end: *const core::ffi::c_void = core::ptr::null();
    };
}
