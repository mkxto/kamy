// Round-trip fixture: deterministic work with recursion, loops, and I/O so the
// protected copy must reproduce identical stdout and exit code.

fn fib(n: u64) -> u64 {
    if n < 2 { n } else { fib(n - 1).wrapping_add(fib(n - 2)) }
}

fn mix(mut x: u64) -> u64 {
    for i in 0..8 {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(i).rotate_left(13);
    }
    x
}

fn main() {
    let mut acc = 0u64;
    for i in 0..24 {
        acc = acc.wrapping_add(fib(i)).wrapping_add(mix(i));
    }
    println!("acc={acc:#018x}");
    std::process::exit((acc & 0x3f) as i32);
}
