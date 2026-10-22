#[path = "../src/native.rs"]
mod native;

#[used]
#[unsafe(no_mangle)]
pub static mut SDK_STATE: [u64; 16] = [
    0,
    0,
    0,
    0x400a_0000_0000_0000,
    0,
    0xc01c_0000_0000_0000,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
];

#[used]
#[unsafe(no_mangle)]
pub static mut HOST_BSS: [u64; 1024] = [0; 1024];

unsafe extern "system" {
    static __ImageBase: u8;
}

fn main() -> anyhow::Result<()> {
    let variant = std::env::var("SDK_VARIANT")?;
    let state = unsafe { core::ptr::addr_of!(SDK_STATE).read_volatile() };
    assert_eq!(state[0], if variant == "baseline" { 0 } else { 12 });
    if variant == "abi" {
        assert_eq!(
            &state[2..8],
            &[
                42,
                0x400a_0000_0000_0000,
                29,
                0xc01c_0000_0000_0000,
                86,
                0x37bf
            ]
        );
    }
    if variant == "bounds" {
        assert_eq!(state[1], 32);
    }
    let bss = core::ptr::addr_of!(HOST_BSS).cast::<u64>();
    assert!((0..1024).all(|index| unsafe { bss.add(index).read_volatile() == 0 }));
    let base = core::ptr::addr_of!(__ImageBase);
    assert_ne!(base as usize, 0x7ffe_0000);
    if let Ok(probes) = std::env::var("SDK_UNWIND_PROBES") {
        unsafe {
            let nt = base.add(0x3c).cast::<u32>().read_unaligned() as usize;
            let image_size = base.add(nt + 24 + 56).cast::<u32>().read_unaligned();
            native::check_ranges(base, image_size, &probes)?;
        }
    }
    println!(
        "trace={} abi={} bounds={} aslr=1 host=exe",
        state[0],
        variant == "abi",
        state[1]
    );
    Ok(())
}
