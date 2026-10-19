//! Standalone DLL export invoker for the differential corpus.
//!
//! Usage: `kamy-loader <dll-abs-path> <export> <retkind> [argtoken ...]`
//! Loads the dll, resolves the export, materializes args from the corpus Arg
//! DSL, calls it, and prints the return value (decimal, masked to retkind) on
//! stdout. On load/proc failure: print nothing, exit non-zero.

fn main() {
    std::process::exit(real_main());
}

#[cfg(not(windows))]
fn real_main() -> i32 {
    eprintln!("kamy-loader requires Windows");
    2
}

#[cfg(windows)]
fn real_main() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 3 {
        eprintln!("usage: kamy-loader <dll> <export> <retkind> [arg ...]");
        return 2;
    }
    let dll = &args[0];
    let export = &args[1];
    let retkind = &args[2];
    let tokens = &args[3..];

    match win::invoke(dll, export, retkind, tokens) {
        Ok(text) => {
            println!("{text}");
            0
        }
        Err(code) => code,
    }
}

#[cfg(windows)]
mod win {
    use std::ffi::c_void;

    type Usize = usize;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryW(name: *const u16) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
        fn FreeLibrary(module: *mut c_void) -> i32;
    }

    /// Owned argument storage; buffers must outlive the call.
    enum Arg {
        Wide(Vec<u16>),
        Ansi(Vec<u8>),
        Int(Usize),
    }

    impl Arg {
        fn as_usize(&self) -> Usize {
            match self {
                Arg::Wide(v) => v.as_ptr() as Usize,
                Arg::Ansi(v) => v.as_ptr() as Usize,
                Arg::Int(n) => *n,
            }
        }
    }

    fn parse_arg(tok: &str) -> Result<Arg, i32> {
        if let Some(lit) = tok.strip_prefix("wstr:") {
            let mut v: Vec<u16> = lit.encode_utf16().collect();
            v.push(0);
            Ok(Arg::Wide(v))
        } else if let Some(lit) = tok.strip_prefix("str:") {
            let mut v: Vec<u8> = lit.as_bytes().to_vec();
            v.push(0);
            Ok(Arg::Ansi(v))
        } else if let Some(n) = tok.strip_prefix("i32:") {
            n.parse::<i32>()
                .map(|x| Arg::Int(x as u32 as Usize))
                .map_err(|_| 3)
        } else if let Some(n) = tok.strip_prefix("u32:") {
            n.parse::<u32>()
                .map(|x| Arg::Int(x as Usize))
                .map_err(|_| 3)
        } else if let Some(n) = tok.strip_prefix("i64:") {
            n.parse::<i64>()
                .map(|x| Arg::Int(x as u64 as Usize))
                .map_err(|_| 3)
        } else if let Some(n) = tok.strip_prefix("u64:") {
            n.parse::<u64>()
                .map(|x| Arg::Int(x as Usize))
                .map_err(|_| 3)
        } else if tok == "ptr:null" {
            Ok(Arg::Int(0))
        } else {
            eprintln!("unknown arg token: {tok}");
            Err(3)
        }
    }

    fn mask_ret(raw: Usize, retkind: &str) -> Result<String, i32> {
        let v = raw as u64;
        Ok(match retkind {
            "i32" => (v as u32 as i32).to_string(),
            "u32" => (v as u32).to_string(),
            "i64" => (v as i64).to_string(),
            "u64" => v.to_string(),
            "bool" => (v != 0).to_string(),
            other => {
                eprintln!("unknown retkind: {other}");
                return Err(3);
            }
        })
    }

    pub(crate) fn invoke(
        dll: &str,
        export: &str,
        retkind: &str,
        tokens: &[String],
    ) -> Result<String, i32> {
        let args: Vec<Arg> = tokens
            .iter()
            .map(|t| parse_arg(t))
            .collect::<Result<_, _>>()?;
        let vals: Vec<Usize> = args.iter().map(Arg::as_usize).collect();

        // Load a uniquely named copy in the same directory: Windows KnownDLLs
        // would otherwise short-circuit `kernel32.dll` (and friends) to the
        // already-loaded system module, so the on-disk bytes under test would
        // never execute. A distinct name forces the loader to map our file.
        use std::os::windows::ffi::OsStrExt as _;
        let src = std::path::Path::new(dll);
        let dir = src.parent().unwrap_or_else(|| std::path::Path::new("."));
        let stem = src
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("kamymod");
        let copy = dir.join(format!("{stem}_kamyload_{}.dll", std::process::id()));
        if std::fs::copy(src, &copy).is_err() {
            return Err(6);
        }
        let mut wide: Vec<u16> = copy.as_os_str().encode_wide().collect();
        wide.push(0);
        let mut name_c: Vec<u8> = export.as_bytes().to_vec();
        name_c.push(0);

        // SAFETY: FFI into kernel32 with NUL-terminated buffers kept alive below.
        let raw = unsafe {
            let module = LoadLibraryW(wide.as_ptr());
            if module.is_null() {
                let _ = std::fs::remove_file(&copy);
                return Err(4);
            }
            let proc_addr = GetProcAddress(module, name_c.as_ptr());
            if proc_addr.is_null() {
                FreeLibrary(module);
                let _ = std::fs::remove_file(&copy);
                return Err(5);
            }
            let ret = call(proc_addr, &vals);
            FreeLibrary(module);
            ret
        };
        let _ = std::fs::remove_file(&copy);
        // Keep arg buffers (string pointees referenced by `vals`) alive past the call.
        drop(args);
        mask_ret(raw, retkind)
    }

    /// Invoke `proc_addr` with pointer-sized args via the system ABI.
    ///
    /// # Safety
    /// `proc_addr` must be a valid function expecting `vals.len()` integer/pointer
    /// arguments under the system calling convention.
    unsafe fn call(proc_addr: *mut c_void, vals: &[Usize]) -> Usize {
        unsafe {
            match vals.len() {
                0 => {
                    let f: extern "system" fn() -> Usize = std::mem::transmute(proc_addr);
                    f()
                }
                1 => {
                    let f: extern "system" fn(Usize) -> Usize = std::mem::transmute(proc_addr);
                    f(vals[0])
                }
                2 => {
                    let f: extern "system" fn(Usize, Usize) -> Usize =
                        std::mem::transmute(proc_addr);
                    f(vals[0], vals[1])
                }
                3 => {
                    let f: extern "system" fn(Usize, Usize, Usize) -> Usize =
                        std::mem::transmute(proc_addr);
                    f(vals[0], vals[1], vals[2])
                }
                4 => {
                    let f: extern "system" fn(Usize, Usize, Usize, Usize) -> Usize =
                        std::mem::transmute(proc_addr);
                    f(vals[0], vals[1], vals[2], vals[3])
                }
                _ => {
                    let f: extern "system" fn(Usize, Usize, Usize, Usize, Usize) -> Usize =
                        std::mem::transmute(proc_addr);
                    f(vals[0], vals[1], vals[2], vals[3], vals[4])
                }
            }
        }
    }
}
