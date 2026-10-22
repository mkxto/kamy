#![no_std]

#[inline(never)]
pub fn integer(value: u64) -> u64 {
    value.wrapping_add(19)
}

#[inline(never)]
#[unsafe(export_name = "sdk_rebuild_scalar_f64")]
pub fn floating(value: f64) -> f64 {
    unsafe { core::ptr::read_volatile(&value) }
}

#[inline(never)]
pub fn mixed(value: (u64, f64)) -> (u64, f64) {
    (value.0.wrapping_add(7), value.1)
}

#[inline(never)]
pub fn aggregate(value: [u64; 3]) -> [u64; 3] {
    [value[0].wrapping_add(3), value[1].wrapping_add(5), value[2].wrapping_add(7)]
}
