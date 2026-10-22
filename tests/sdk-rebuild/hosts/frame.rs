#![no_std]

use core::ffi::c_void;

#[unsafe(export_name = "_fltused")]
pub static FLTUSED: i32 = 0x9875;

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "system" fn frame_mix6(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> u64 {
    (a.wrapping_add(b.wrapping_mul(3)) ^ c.wrapping_mul(5).wrapping_add(d))
        .wrapping_add(e.wrapping_mul(7))
        .wrapping_sub(f.wrapping_mul(11))
}

#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "system" fn frame_touch(object: *mut u64) -> u64 {
    unsafe {
        let first = object.read_volatile();
        let third = object.add(2).read_volatile();
        object.add(1).write_volatile(first.wrapping_add(third));
        (first ^ third).wrapping_add(object.add(1).read_volatile())
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "system" fn frame_stack6(seed: u64) -> u64 {
    let mut object = [seed.wrapping_add(11), seed ^ 0x55, seed.wrapping_mul(3), seed.wrapping_add(101)];
    let pointer = object.as_mut_ptr();
    unsafe {
        let touched = frame_touch(pointer);
        let result = frame_mix6(
            pointer.read_volatile(),
            pointer.add(1).read_volatile(),
            pointer.add(2).read_volatile(),
            pointer.add(3).read_volatile(),
            touched,
            seed,
        );
        result ^ pointer.add(1).read_volatile()
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "system" fn frame_pinned(seed: u64) -> u64 {
    let first = frame_mix6(seed, 2, 3, 5, 7, 11);
    let second = frame_mix6(seed.wrapping_add(1), 13, 17, 19, 23, 29);
    first.wrapping_mul(13).wrapping_add(second)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "system" fn frame_mixed(a: u64, b: f64, c: u64, d: f64, e: u64, f: f64) -> f64 {
    if a.wrapping_mul(3).wrapping_add(c).wrapping_add(e) == 23 {
        b + d + f
    } else {
        b - d - f
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "system" fn frame_recursive(depth: u64, seed: u64, trace: *mut usize) -> u64 {
    let mut object = core::mem::MaybeUninit::<[u64; 512]>::uninit();
    let pointer = object.as_mut_ptr().cast::<u64>();
    unsafe {
        pointer.write_volatile(seed.wrapping_add(depth));
        pointer.add(511).write_volatile(seed ^ depth);
        trace.write_volatile(pointer as usize);
        let child = if depth == 0 {
            seed.wrapping_mul(17).wrapping_add(3)
        } else {
            frame_recursive(depth - 1, seed.wrapping_add(3), trace.add(1))
        };
        child
            .wrapping_add(pointer.read_volatile().wrapping_mul(5))
            .wrapping_add(pointer.add(511).read_volatile())
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "system" fn frame_large(seed: u64) -> u64 {
    let mut object = core::mem::MaybeUninit::<[u64; 3072]>::uninit();
    let pointer = object.as_mut_ptr().cast::<u64>();
    let mut index = 0usize;
    while index < 3072 {
        unsafe { pointer.add(index).write_volatile(seed.wrapping_add((index as u64).wrapping_mul(7))); }
        index += 1;
    }
    let mut sum = 0u64;
    while index != 0 {
        index -= 1;
        sum = sum.wrapping_add(unsafe { pointer.add(index).read_volatile() });
    }
    sum
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "system" fn frame_saves(seed: u64) -> u64 {
    let mut object = core::mem::MaybeUninit::<[u64; 2048]>::uninit();
    let pointer = object.as_mut_ptr().cast::<u64>();
    let result: u64;
    unsafe {
        pointer.write_volatile(seed);
        pointer.add(2047).write_volatile(seed.wrapping_add(9));
        core::arch::asm!(
            "test {object}, {object}",
            "mov r12, {seed}",
            "xor r12, 0x5a",
            "movq xmm6, r12",
            "movq {result}, xmm6",
            seed = in(reg) seed,
            object = in(reg) pointer,
            result = lateout(reg) result,
            lateout("r12") _,
            lateout("xmm6") _,
            options(nostack),
        );
        result
            .wrapping_add(pointer.read_volatile())
            .wrapping_add(pointer.add(2047).read_volatile())
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(_: *mut c_void, _: u32, _: *mut c_void) -> i32 {
    1
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { core::arch::asm!("int 0x29", in("ecx") 7u32, options(noreturn)); }
}
