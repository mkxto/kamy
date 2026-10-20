//! Child-process execution harness for the kamy protector test corpus.
//!
//! Two execution modes are provided:
//!
//! * [`run`] launches the target with no debugger attached. It is the fast
//!   path: stdio is captured through pipes, a Job Object guarantees the child
//!   (and any descendants) is torn down, and WER popups are suppressed so a
//!   crash terminates promptly with the exception code as the exit code. No
//!   fault location is recovered in this mode ([`RunOutcome::fault`] is always
//!   `None`).
//! * [`run_traced`] launches the target under a lightweight debug loop
//!   (`DEBUG_ONLY_THIS_PROCESS`). It observes the image base from the process
//!   creation event and, on the first-chance access violation, reports the
//!   faulting address together with the module-relative RVA in
//!   [`RunOutcome::fault`]. This is slower but tells the caller *where* the
//!   protected image crashed.
//!
//! Both modes share pipe draining (on background threads, to avoid
//! pipe-buffer deadlock), optional `cwd`/`env` overrides, stdin feeding, and a
//! wall-clock timeout enforced via the Job Object.

use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr::null_mut;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use windows::Win32::Foundation::{
    CloseHandle, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, HANDLE, HANDLE_FLAG_INHERIT,
    HANDLE_FLAGS, SetHandleInformation, TRUE, WAIT_TIMEOUT,
};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::Diagnostics::Debug::{
    CREATE_PROCESS_DEBUG_EVENT, ContinueDebugEvent, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT,
    EXIT_PROCESS_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX,
    SetErrorMode, WaitForDebugEvent,
};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
    DEBUG_ONLY_THIS_PROCESS, GetExitCodeProcess, INFINITE, PROCESS_INFORMATION, ResumeThread,
    STARTF_USESTDHANDLES, STARTUPINFOW, WaitForSingleObject,
};
use windows::core::{PCWSTR, PWSTR};

const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC000_0005;
const EXCEPTION_BREAKPOINT: u32 = 0x8000_0003;

/// How to launch a target process.
#[derive(Clone, Debug, Default)]
pub struct RunOptions {
    pub exe: PathBuf,
    pub args: Vec<String>,
    pub stdin: Vec<u8>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<PathBuf>,
    /// Wall-clock limit; [`Duration::ZERO`] means no timeout.
    pub timeout: Duration,
}

/// A first-chance access violation observed under [`run_traced`].
#[derive(Clone, Copy, Debug)]
pub struct Fault {
    pub code: u32,
    pub address: u64,
    pub image_base: u64,
    pub rva: u64,
}

/// Result of executing a target process.
#[derive(Clone, Debug, Default)]
pub struct RunOutcome {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
    pub fault: Option<Fault>,
}

/// Run the target with no debugger attached.
///
/// Stdio is captured, a Job Object kills the child tree on completion, and
/// [`RunOutcome::fault`] is always `None`.
pub fn run(opts: &RunOptions) -> Result<RunOutcome> {
    execute(opts, false)
}

/// Run the target under a debug loop that reports the first faulting RVA.
///
/// On the first-chance `EXCEPTION_ACCESS_VIOLATION`, [`RunOutcome::fault`] is
/// populated with the faulting address and its offset from the image base.
pub fn run_traced(opts: &RunOptions) -> Result<RunOutcome> {
    execute(opts, true)
}

/// RAII wrapper that closes a Win32 handle on drop unless ownership is taken.
struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn get(&self) -> HANDLE {
        self.0
    }

    /// Relinquish ownership; the caller becomes responsible for closing it.
    fn take(&mut self) -> HANDLE {
        std::mem::take(&mut self.0)
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// `HANDLE` is not `Send`; this wrapper asserts the raw value is safe to move
/// to a draining thread that holds the sole reference to that pipe end.
#[derive(Clone, Copy)]
struct SendHandle(HANDLE);

// SAFETY: each wrapped handle is handed to exactly one thread, which owns it
// for the remainder of its lifetime.
unsafe impl Send for SendHandle {}

fn wide(os: &std::ffi::OsStr) -> Vec<u16> {
    os.encode_wide().chain(std::iter::once(0)).collect()
}

/// Quote a single argument following the Windows `CommandLineToArgvW` rules.
fn quote_arg(arg: &str, out: &mut String) {
    if !arg.is_empty() && !arg.contains([' ', '\t', '\n', '\u{b}', '"']) {
        out.push_str(arg);
        return;
    }
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                for _ in 0..(backslashes * 2 + 1) {
                    out.push('\\');
                }
                backslashes = 0;
                out.push('"');
            }
            _ => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push(c);
            }
        }
    }
    for _ in 0..(backslashes * 2) {
        out.push('\\');
    }
    out.push('"');
}

fn build_command_line(opts: &RunOptions) -> Vec<u16> {
    let mut cmd = String::new();
    quote_arg(&opts.exe.to_string_lossy(), &mut cmd);
    for arg in &opts.args {
        cmd.push(' ');
        quote_arg(arg, &mut cmd);
    }
    cmd.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Build a `CREATE_UNICODE_ENVIRONMENT` block merging the parent environment
/// with the caller's overrides. Returns `None` when there are no overrides so
/// the child simply inherits the parent block.
fn build_env_block(env: &[(String, String)]) -> Option<Vec<u16>> {
    if env.is_empty() {
        return None;
    }
    // Windows environment variable names are case-insensitive; key the merge by
    // the upper-cased name and keep the block sorted (required by the API).
    use std::collections::BTreeMap;
    let mut map: BTreeMap<String, (String, String)> = BTreeMap::new();
    for (k, v) in std::env::vars() {
        map.insert(k.to_uppercase(), (k, v));
    }
    for (k, v) in env {
        map.insert(k.to_uppercase(), (k.clone(), v.clone()));
    }
    let mut block: Vec<u16> = Vec::new();
    for (k, v) in map.values() {
        block.extend(format!("{k}={v}").encode_utf16());
        block.push(0);
    }
    block.push(0);
    Some(block)
}

/// Read a pipe end to EOF (signalled by `ERROR_BROKEN_PIPE`), then close it.
fn drain_pipe(h: HANDLE) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        let mut read = 0u32;
        let r = unsafe { ReadFile(h, Some(&mut buf), Some(&mut read), None) };
        if r.is_err() || read == 0 {
            break;
        }
        out.extend_from_slice(&buf[..read as usize]);
    }
    unsafe {
        let _ = CloseHandle(h);
    }
    out
}

/// Write the whole buffer to a pipe end, then close it to signal EOF.
fn feed_pipe(h: HANDLE, data: &[u8]) {
    let mut off = 0usize;
    while off < data.len() {
        let mut written = 0u32;
        let r = unsafe { WriteFile(h, Some(&data[off..]), Some(&mut written), None) };
        if r.is_err() || written == 0 {
            break;
        }
        off += written as usize;
    }
    unsafe {
        let _ = CloseHandle(h);
    }
}

fn execute(opts: &RunOptions, traced: bool) -> Result<RunOutcome> {
    // Inherited by the child since we do not pass CREATE_DEFAULT_ERROR_MODE:
    // suppress the critical-error and GP-fault WER dialogs so a crash cannot
    // wedge the harness on a modal popup.
    unsafe {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    }

    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: TRUE,
    };

    // stdout / stderr: parent reads, child writes. stdin: child reads, parent writes.
    let mut out_r = HANDLE::default();
    let mut out_w = HANDLE::default();
    let mut err_r = HANDLE::default();
    let mut err_w = HANDLE::default();
    let mut in_r = HANDLE::default();
    let mut in_w = HANDLE::default();
    unsafe {
        CreatePipe(&mut out_r, &mut out_w, Some(&sa), 0).context("CreatePipe(stdout)")?;
        CreatePipe(&mut err_r, &mut err_w, Some(&sa), 0).context("CreatePipe(stderr)")?;
        CreatePipe(&mut in_r, &mut in_w, Some(&sa), 0).context("CreatePipe(stdin)")?;
    }
    let out_r = OwnedHandle(out_r);
    let child_out_w = OwnedHandle(out_w);
    let err_r = OwnedHandle(err_r);
    let child_err_w = OwnedHandle(err_w);
    let child_in_r = OwnedHandle(in_r);
    let in_w = OwnedHandle(in_w);

    // The parent-side ends must not be inheritable, otherwise the child keeps a
    // live copy and the pipes never reach EOF (classic redirection deadlock).
    unsafe {
        SetHandleInformation(out_r.get(), HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0))?;
        SetHandleInformation(err_r.get(), HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0))?;
        SetHandleInformation(in_w.get(), HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0))?;
    }

    // Job Object: kill the whole tree when the job closes and convert an
    // unhandled exception into a prompt termination (no WER escalation).
    let hjob =
        OwnedHandle(unsafe { CreateJobObjectW(None, PCWSTR::null()) }.context("CreateJobObjectW")?);
    let mut job_info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    job_info.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    unsafe {
        SetInformationJobObject(
            hjob.get(),
            JobObjectExtendedLimitInformation,
            &job_info as *const _ as *const c_void,
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
        .context("SetInformationJobObject")?;
    }

    let appname = wide(opts.exe.as_os_str());
    let mut cmdline = build_command_line(opts);
    let env_block = build_env_block(&opts.env);
    let cwd_wide = opts.cwd.as_ref().map(|p| wide(p.as_os_str()));

    let si = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESTDHANDLES,
        hStdInput: child_in_r.get(),
        hStdOutput: child_out_w.get(),
        hStdError: child_err_w.get(),
        ..Default::default()
    };

    let mut flags = CREATE_SUSPENDED | CREATE_NO_WINDOW;
    if env_block.is_some() {
        flags |= CREATE_UNICODE_ENVIRONMENT;
    }
    if traced {
        flags |= DEBUG_ONLY_THIS_PROCESS;
    }

    let env_ptr = env_block.as_ref().map(|b| b.as_ptr() as *const c_void);
    let cwd_pcwstr = match &cwd_wide {
        Some(w) => PCWSTR(w.as_ptr()),
        None => PCWSTR::null(),
    };

    let mut pi = PROCESS_INFORMATION::default();
    unsafe {
        CreateProcessW(
            PCWSTR(appname.as_ptr()),
            PWSTR(cmdline.as_mut_ptr()),
            None,
            None,
            TRUE,
            flags,
            env_ptr,
            cwd_pcwstr,
            &si,
            &mut pi,
        )
        .with_context(|| format!("CreateProcessW({})", opts.exe.display()))?;
    }
    let hprocess = OwnedHandle(pi.hProcess);
    let hthread = OwnedHandle(pi.hThread);

    // Confine the child to the job before it runs, so it can never escape.
    unsafe {
        AssignProcessToJobObject(hjob.get(), hprocess.get()).context("AssignProcessToJobObject")?;
    }

    // Close the parent's copies of the child-side ends so EOF propagates.
    drop(child_out_w);
    drop(child_err_w);
    drop(child_in_r);

    // Start draining before the child runs to avoid pipe-buffer deadlock.
    let mut out_r = out_r;
    let mut err_r = err_r;
    let mut in_w = in_w;
    let out_h = SendHandle(out_r.take());
    let err_h = SendHandle(err_r.take());
    let in_h = SendHandle(in_w.take());
    let out_t = std::thread::spawn(move || {
        let h = out_h;
        drain_pipe(h.0)
    });
    let err_t = std::thread::spawn(move || {
        let h = err_h;
        drain_pipe(h.0)
    });
    let stdin_data = opts.stdin.clone();
    let in_t = std::thread::spawn(move || {
        let h = in_h;
        feed_pipe(h.0, &stdin_data)
    });

    unsafe {
        ResumeThread(hthread.get());
    }

    let mut outcome = RunOutcome::default();

    if traced {
        debug_loop(opts, &pi, &hjob, &mut outcome)?;
    } else {
        let wait_ms = timeout_ms(opts.timeout);
        let wr = unsafe { WaitForSingleObject(hprocess.get(), wait_ms) };
        if wr == WAIT_TIMEOUT {
            outcome.timed_out = true;
            unsafe {
                let _ = TerminateJobObject(hjob.get(), 1);
            }
        } else {
            let mut code = 0u32;
            unsafe {
                GetExitCodeProcess(hprocess.get(), &mut code).context("GetExitCodeProcess")?;
            }
            outcome.exit_code = Some(code as i32);
        }
    }

    let _ = in_t.join();
    outcome.stdout = out_t.join().unwrap_or_default();
    outcome.stderr = err_t.join().unwrap_or_default();

    Ok(outcome)
}

/// Convert a timeout `Duration` to a Win32 millisecond value (`INFINITE` for zero).
fn timeout_ms(timeout: Duration) -> u32 {
    if timeout.is_zero() {
        INFINITE
    } else {
        timeout.as_millis().min(u32::from(u16::MAX) as u128 * 65536) as u32
    }
}

/// Debug-event pump: records the image base, reports the first faulting RVA,
/// and captures the exit code, while honoring the timeout via a deadline.
fn debug_loop(
    opts: &RunOptions,
    pi: &PROCESS_INFORMATION,
    hjob: &OwnedHandle,
    outcome: &mut RunOutcome,
) -> Result<()> {
    let deadline = if opts.timeout.is_zero() {
        None
    } else {
        Some(Instant::now() + opts.timeout)
    };
    let mut image_base: u64 = 0;

    loop {
        let wait_ms = match deadline {
            None => INFINITE,
            Some(d) => {
                let now = Instant::now();
                if now >= d {
                    outcome.timed_out = true;
                    unsafe {
                        let _ = TerminateJobObject(hjob.get(), 1);
                    }
                    break;
                }
                // Cap each wait so the deadline is re-checked responsively.
                ((d - now).as_millis().min(50) as u32).max(1)
            }
        };

        let mut ev = DEBUG_EVENT::default();
        let r = unsafe { WaitForDebugEvent(&mut ev, wait_ms) };
        if r.is_err() {
            match deadline {
                // A finite per-iteration wait timed out; loop to re-check.
                Some(_) => continue,
                None => bail!("WaitForDebugEvent failed"),
            }
        }

        match ev.dwDebugEventCode {
            CREATE_PROCESS_DEBUG_EVENT => {
                let ci = unsafe { ev.u.CreateProcessInfo };
                image_base = ci.lpBaseOfImage as usize as u64;
                if !ci.hFile.is_invalid() {
                    unsafe {
                        let _ = CloseHandle(ci.hFile);
                    }
                }
                continue_event(&ev, DBG_CONTINUE.0)?;
            }
            LOAD_DLL_DEBUG_EVENT => {
                let dll = unsafe { ev.u.LoadDll };
                if !dll.hFile.is_invalid() {
                    unsafe {
                        let _ = CloseHandle(dll.hFile);
                    }
                }
                continue_event(&ev, DBG_CONTINUE.0)?;
            }
            EXCEPTION_DEBUG_EVENT => {
                let ex = unsafe { ev.u.Exception };
                let code = ex.ExceptionRecord.ExceptionCode.0 as u32;
                if code == EXCEPTION_ACCESS_VIOLATION {
                    let address = ex.ExceptionRecord.ExceptionAddress as usize as u64;
                    outcome.fault = Some(Fault {
                        code,
                        address,
                        image_base,
                        rva: address.wrapping_sub(image_base),
                    });
                    unsafe {
                        let _ = TerminateJobObject(hjob.get(), 1);
                    }
                    break;
                } else if code == EXCEPTION_BREAKPOINT {
                    // Initial / debugger breakpoints: swallow and continue.
                    continue_event(&ev, DBG_CONTINUE.0)?;
                } else {
                    // Let the target's own handlers see other exceptions.
                    continue_event(&ev, DBG_EXCEPTION_NOT_HANDLED.0)?;
                }
            }
            EXIT_PROCESS_DEBUG_EVENT => {
                let code = unsafe { ev.u.ExitProcess.dwExitCode };
                outcome.exit_code = Some(code as i32);
                continue_event(&ev, DBG_CONTINUE.0)?;
                break;
            }
            _ => {
                continue_event(&ev, DBG_CONTINUE.0)?;
            }
        }
    }

    // The process handle is unused here; the job tore the child down. Suppress
    // the unused-binding by referencing it explicitly.
    let _ = pi.hProcess;
    Ok(())
}

fn continue_event(ev: &DEBUG_EVENT, status: i32) -> Result<()> {
    unsafe {
        ContinueDebugEvent(
            ev.dwProcessId,
            ev.dwThreadId,
            windows::Win32::Foundation::NTSTATUS(status),
        )
        .context("ContinueDebugEvent")
    }
}
