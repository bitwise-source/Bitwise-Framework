//! # Bitwise Debugger
//!
//! Debugger multi-plataforma. En Linux usa ptrace directamente vía libc;
//! en macOS/Windows expone un backend simulado para desarrollo y tests.
//!
//! Ciclo: spawn → breakpoint → continue → step → regs → mem read/write.

use bitwise_core::arch::Instruction;
use bitwise_disasm::{Disassembler, DisasmError};
use std::collections::BTreeMap;
use std::collections::BTreeSet;

#[derive(Debug, thiserror::Error)]
pub enum DebugError {
    #[error("ptrace error: {0}")]
    Ptrace(String),
    #[error("process not running")]
    NotRunning,
    #[error("invalid address: 0x{0:x}")]
    InvalidAddress(u64),
    #[error("no such breakpoint: 0x{0:x}")]
    NoBreakpoint(u64),
    #[error("unsupported on this platform: {0}")]
    UnsupportedPlatform(String),
    #[error("wait error: {0}")]
    Wait(String),
    #[error("spawn error: {0}")]
    Spawn(String),
    #[error(transparent)]
    Disasm(#[from] DisasmError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, DebugError>;

/// Registro de CPU en el proceso depurado (nombre → valor).
pub type RegSet = BTreeMap<String, u64>;

/// Estado de un breakpoint.
#[derive(Debug, Clone)]
pub struct Breakpoint {
    pub address: u64,
    /// Byte original guardado para restaurar
    pub original_byte: u8,
    /// ¿Está habilitado?
    pub enabled: bool,
    /// ¿Fue golpeado en el último stop?
    pub hit: bool,
}

/// Evento recibido al esperar al tracee.
#[derive(Debug, Clone)]
pub enum StopEvent {
    /// El tracee se detuvo por un SIGTRAP (breakpoint o step)
    Trap,
    /// Señal recibida (número)
    Signal(i32),
    /// El proceso terminó (exit code)
    Exited(i32),
    /// Terminado por señal
    KilledBySignal(i32),
}

// ============================================================================
// Backend trait — cada OS implementa el suyo
// ============================================================================

pub trait DebugBackend {
    /// Inicia el programa bajo control del debugger.
    fn spawn(&mut self, path: &str, args: &[String]) -> Result<u32>;
    /// Continúa la ejecución.
    fn cont(&mut self) -> Result<()>;
    /// Ejecuta una sola instrucción.
    fn step(&mut self) -> Result<()>;
    /// Lee registros del tracee.
    fn read_regs(&mut self) -> Result<RegSet>;
    /// Escribe un registro.
    fn write_reg(&mut self, name: &str, value: u64) -> Result<()>;
    /// Lee memoria del tracee.
    fn read_mem(&mut self, addr: u64, len: usize) -> Result<Vec<u8>>;
    /// Escribe memoria del tracee.
    fn write_mem(&mut self, addr: u64, data: &[u8]) -> Result<()>;
    /// Espera el próximo evento del tracee.
    fn wait(&mut self) -> Result<StopEvent>;
    /// Mata al tracee.
    fn kill(&mut self) -> Result<()>;
}

// ============================================================================
// Linux ptrace backend
// ============================================================================

#[cfg(target_os = "linux")]
pub mod linux_backend {
    use super::*;
    use std::ptr;

    const PTRACE_TRACEME: u64 = 0;
    const PTRACE_PEEKTEXT: u64 = 1;
    const PTRACE_PEEKDATA: u64 = 2;
    const PTRACE_POKETEXT: u64 = 4;
    const PTRACE_POKEDATA: u64 = 5;
    const PTRACE_CONT: u64 = 7;
    const PTRACE_SINGLESTEP: u64 = 9;
    const PTRACE_GETREGS: u64 = 12;
    const PTRACE_SETREGS: u64 = 13;

    const INT3: u64 = 0xCC;

    // user_regs_struct x86_64 (offsets en orden)
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default)]
    pub struct UserRegs {
        pub r15: u64, pub r14: u64, pub r13: u64, pub r12: u64,
        pub rbp: u64, pub rbx: u64, pub r11: u64, pub r10: u64,
        pub r9: u64, pub r8: u64, pub rax: u64, pub rcx: u64,
        pub rdx: u64, pub rsi: u64, pub rdi: u64,
        pub orig_rax: u64, pub rip: u64, pub cs: u64,
        pub eflags: u64, pub rsp: u64, pub ss: u64, pub fs_base: u64,
        pub gs_base: u64, pub ds: u64, pub es: u64, pub fs: u64, pub gs: u64,
    }

    impl UserRegs {
        pub fn to_map(&self) -> RegSet {
            let mut m = RegSet::new();
            m.insert("r15".into(), self.r15);
            m.insert("r14".into(), self.r14);
            m.insert("r13".into(), self.r13);
            m.insert("r12".into(), self.r12);
            m.insert("rbp".into(), self.rbp);
            m.insert("rbx".into(), self.rbx);
            m.insert("r11".into(), self.r11);
            m.insert("r10".into(), self.r10);
            m.insert("r9".into(), self.r9);
            m.insert("r8".into(), self.r8);
            m.insert("rax".into(), self.rax);
            m.insert("rcx".into(), self.rcx);
            m.insert("rdx".into(), self.rdx);
            m.insert("rsi".into(), self.rsi);
            m.insert("rdi".into(), self.rdi);
            m.insert("rip".into(), self.rip);
            m.insert("rsp".into(), self.rsp);
            m.insert("eflags".into(), self.eflags);
            m
        }

        pub fn set_field(&mut self, name: &str, value: u64) -> bool {
            match name {
                "r15" => self.r15 = value,
                "r14" => self.r14 = value,
                "r13" => self.r13 = value,
                "r12" => self.r12 = value,
                "rbp" => self.rbp = value,
                "rbx" => self.rbx = value,
                "r11" => self.r11 = value,
                "r10" => self.r10 = value,
                "r9" => self.r9 = value,
                "r8" => self.r8 = value,
                "rax" => self.rax = value,
                "rcx" => self.rcx = value,
                "rdx" => self.rdx = value,
                "rsi" => self.rsi = value,
                "rdi" => self.rdi = value,
                "rip" => self.rip = value,
                "rsp" => self.rsp = value,
                "eflags" => self.eflags = value,
                _ => return false,
            }
            true
        }
    }

    unsafe extern "C" {
        fn ptrace(request: u64, pid: i32, addr: *mut core::ffi::c_void, data: *mut core::ffi::c_void) -> i64;
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        fn fork() -> i32;
        fn execv(path: *const u8, argv: *const *const u8) -> i32;
        fn kill(pid: i32, sig: i32) -> i32;
    }

    pub struct LinuxBackend {
        pub pid: Option<i32>,
    }

    impl LinuxBackend {
        pub fn new() -> Self {
            Self { pid: None }
        }
    }

    impl Default for LinuxBackend {
        fn default() -> Self {
            Self::new()
        }
    }

    impl DebugBackend for LinuxBackend {
        fn spawn(&mut self, path: &str, args: &[String]) -> Result<u32> {
            unsafe {
                let pid = fork();
                if pid < 0 {
                    return Err(DebugError::Spawn("fork failed".into()));
                }
                if pid == 0 {
                    // hijo: pedir ser trazado antes de exec
                    ptrace(PTRACE_TRACEME, 0, ptr::null_mut(), ptr::null_mut());
                    let mut argv_vec: Vec<std::ffi::CString> = Vec::new();
                    let cpath = std::ffi::CString::new(path).map_err(|e| DebugError::Spawn(e.to_string()))?;
                    argv_vec.push(cpath.clone());
                    for a in args {
                        argv_vec.push(std::ffi::CString::new(a.clone()).map_err(|e| DebugError::Spawn(e.to_string()))?);
                    }
                    let mut argv: Vec<*const u8> = argv_vec.iter().map(|c| c.as_ptr() as *const u8).collect();
                    argv.push(ptr::null());
                    execv(cpath.as_ptr() as *const u8, argv.as_ptr());
                    // exec falló
                    std::process::exit(127);
                }
                // padre: esperar el SIGTRAP post-exec
                let mut status: i32 = 0;
                if waitpid(pid, &mut status, 0) < 0 {
                    return Err(DebugError::Wait("waitpid post-exec failed".into()));
                }
                self.pid = Some(pid);
                Ok(pid as u32)
            }
        }

        fn cont(&mut self) -> Result<()> {
            let pid = self.pid.ok_or(DebugError::NotRunning)?;
            let rv = unsafe { ptrace(PTRACE_CONT, pid, ptr::null_mut(), ptr::null_mut()) };
            if rv < 0 {
                return Err(DebugError::Ptrace("PTRACE_CONT failed".into()));
            }
            Ok(())
        }

        fn step(&mut self) -> Result<()> {
            let pid = self.pid.ok_or(DebugError::NotRunning)?;
            let rv = unsafe { ptrace(PTRACE_SINGLESTEP, pid, ptr::null_mut(), ptr::null_mut()) };
            if rv < 0 {
                return Err(DebugError::Ptrace("PTRACE_SINGLESTEP failed".into()));
            }
            Ok(())
        }

        fn read_regs(&mut self) -> Result<RegSet> {
            let pid = self.pid.ok_or(DebugError::NotRunning)?;
            let mut regs = UserRegs::default();
            let rv = unsafe {
                ptrace(PTRACE_GETREGS, pid, ptr::null_mut(), &mut regs as *mut UserRegs as *mut core::ffi::c_void)
            };
            if rv < 0 {
                return Err(DebugError::Ptrace("PTRACE_GETREGS failed".into()));
            }
            Ok(regs.to_map())
        }

        fn write_reg(&mut self, name: &str, value: u64) -> Result<()> {
            let pid = self.pid.ok_or(DebugError::NotRunning)?;
            let mut regs = UserRegs::default();
            unsafe {
                let rv = ptrace(PTRACE_GETREGS, pid, ptr::null_mut(), &mut regs as *mut UserRegs as *mut core::ffi::c_void);
                if rv < 0 {
                    return Err(DebugError::Ptrace("PTRACE_GETREGS failed".into()));
                }
                if !regs.set_field(name, value) {
                    return Err(DebugError::Ptrace(format!("unknown register: {}", name)));
                }
                let rv = ptrace(PTRACE_SETREGS, pid, ptr::null_mut(), &mut regs as *mut UserRegs as *mut core::ffi::c_void);
                if rv < 0 {
                    return Err(DebugError::Ptrace("PTRACE_SETREGS failed".into()));
                }
            }
            Ok(())
        }

        fn read_mem(&mut self, addr: u64, len: usize) -> Result<Vec<u8>> {
            let pid = self.pid.ok_or(DebugError::NotRunning)?;
            let mut out = Vec::with_capacity(len);
            let mut offset = 0usize;
            while offset < len {
                let cur = addr + offset as u64;
                let word = unsafe {
                    ptrace(PTRACE_PEEKDATA, pid, cur as *mut core::ffi::c_void, ptr::null_mut())
                };
                if word == -1 {
                    return Err(DebugError::InvalidAddress(cur));
                }
                let bytes = (word as u64).to_le_bytes();
                let take = (len - offset).min(8);
                out.extend_from_slice(&bytes[..take]);
                offset += 8;
            }
            Ok(out)
        }

        fn write_mem(&mut self, addr: u64, data: &[u8]) -> Result<()> {
            let pid = self.pid.ok_or(DebugError::NotRunning)?;
            // leer-modificar-escribir por palabra de 8 bytes
            let mut offset = 0usize;
            while offset < data.len() {
                let cur = addr + offset as u64;
                let word = unsafe {
                    ptrace(PTRACE_PEEKDATA, pid, cur as *mut core::ffi::c_void, ptr::null_mut())
                };
                if word == -1 {
                    return Err(DebugError::InvalidAddress(cur));
                }
                let mut bytes = (word as u64).to_le_bytes();
                let take = (data.len() - offset).min(8);
                bytes[..take].copy_from_slice(&data[offset..offset + take]);
                let new_word = u64::from_le_bytes(bytes);
                let rv = unsafe {
                    ptrace(PTRACE_POKEDATA, pid, cur as *mut core::ffi::c_void, new_word as *mut core::ffi::c_void)
                };
                if rv < 0 {
                    return Err(DebugError::Ptrace("PTRACE_POKEDATA failed".into()));
                }
                offset += 8;
            }
            Ok(())
        }

        fn wait(&mut self) -> Result<StopEvent> {
            let pid = self.pid.ok_or(DebugError::NotRunning)?;
            let mut status: i32 = 0;
            unsafe {
                if waitpid(pid, &mut status, 0) < 0 {
                    return Err(DebugError::Wait("waitpid failed".into()));
                }
                if libc_wifexited(status) {
                    Ok(StopEvent::Exited(libc_wexitstatus(status)))
                } else if libc_wifstopped(status) {
                    let sig = libc_wstopsig(status);
                    if sig == 5 {
                        Ok(StopEvent::Trap)
                    } else {
                        Ok(StopEvent::Signal(sig))
                    }
                } else if libc_wifsignaled(status) {
                    Ok(StopEvent::KilledBySignal(libc_wtermsig(status)))
                } else {
                    Ok(StopEvent::Trap)
                }
            }
        }

        fn kill(&mut self) -> Result<()> {
            if let Some(pid) = self.pid.take() {
                unsafe {
                    kill(pid, 9);
                }
            }
            Ok(())
        }
    }

    // macros de wait status (de libc)
    fn libc_wifexited(status: i32) -> bool {
        (status & 0x7f) == 0
    }
    fn libc_wexitstatus(status: i32) -> i32 {
        (status >> 8) & 0xff
    }
    fn libc_wifstopped(status: i32) -> bool {
        (status & 0xff) == 0x7f
    }
    fn libc_wstopsig(status: i32) -> i32 {
        (status >> 8) & 0xff
    }
    fn libc_wifsignaled(status: i32) -> bool {
        let sig = status & 0x7f;
        sig != 0 && sig != 0x7f
    }
    fn libc_wtermsig(status: i32) -> i32 {
        status & 0x7f
    }
}

// ============================================================================
// Windows Debug API backend (skeleton — usa DebugActiveProcess / WaitForDebugEvent)
// ============================================================================
//
//  En Windows, la depuración nativa se hace vía la Win32 Debug API:
//    - DebugActiveProcess(pid)         →  attach a un proceso vivo
//    - CreateProcess(..., DEBUG_PROCESS)  →  spawn
//    - WaitForDebugEvent / ContinueDebugEvent
//    - ReadProcessMemory / WriteProcessMemory
//    - GetThreadContext / SetThreadContext (CONTEXT struct por arquitectura)
//
//  Esta primera versión expone un stub compilable: detecta la plataforma y
//  devuelve un error claro cuando se intenta usar en un host no-Windows.
//  El esqueleto es lo bastante completo para que un usuario en Windows lo
//  termine conectando con los bindings del crate `windows` o FFI directo.

#[cfg(target_os = "windows")]
pub mod windows_backend {
    use super::*;
    use std::ptr;

    // Las firmas aquí son las mínimas para spawn/wait/read mem. Una
    // implementación real usa bindings del crate `windows` (o `winapi`)
    // porque las estructuras CONTEXT son extensas (528+ bytes).
    extern "system" {
        fn DebugActiveProcess(dwProcessId: u32) -> i32;
        fn DebugBreakProcess(hProcess: *mut core::ffi::c_void) -> i32;
        fn ContinueDebugEvent(
            dwProcessId: u32,
            dwThreadId: u32,
            dwContinueStatus: u32,
        ) -> i32;
        fn FlushInstructionCache(
            hProcess: *mut core::ffi::c_void,
            lpBaseAddress: *const core::ffi::c_void,
            dwSize: usize,
        ) -> i32;
    }

    pub struct WindowsBackend {
        pub pid: Option<u32>,
    }

    impl WindowsBackend {
        pub fn new() -> Self {
            Self { pid: None }
        }
    }

    impl Default for WindowsBackend {
        fn default() -> Self {
            Self::new()
        }
    }

    impl DebugBackend for WindowsBackend {
        fn spawn(&mut self, _path: &str, _args: &[String]) -> Result<u32> {
            // Implementación real: CreateProcess con flag DEBUG_PROCESS
            // devolvería el PID; aquí simulamos con DebugActiveProcess
            // (asume que el usuario corre el proceso con un debugger attached
            // o usa una variante con CreateProcess para una implementación completa).
            Err(DebugError::UnsupportedPlatform(
                "Windows debugger backend: implementación parcial. \
                 Conectar con `windows` crate o `winapi` para spawn/breakpoints completos."
                    .into(),
            ))
        }

        fn cont(&mut self) -> Result<()> {
            let pid = self.pid.ok_or(DebugError::NotRunning)?;
            // DBG_CONTINUE = 0x00010002
            let rv = unsafe { ContinueDebugEvent(pid, 0, 0x00010002) };
            if rv == 0 {
                return Err(DebugError::Ptrace("ContinueDebugEvent failed".into()));
            }
            Ok(())
        }

        fn step(&mut self) -> Result<()> {
            // En Windows se hace con SetThreadContext + TF bit en EFLAGS
            // (requiere la struct CONTEXT completa). Stub.
            Err(DebugError::UnsupportedPlatform(
                "Windows single-step: implementar con GetThreadContext + SetThreadContext".into(),
            ))
        }

        fn read_regs(&mut self) -> Result<RegSet> {
            // GetThreadContext con CONTEXT_INTEGER | CONTEXT_CONTROL | CONTEXT_INTEGER
            Err(DebugError::UnsupportedPlatform(
                "Windows read_regs: implementar con GetThreadContext".into(),
            ))
        }

        fn write_reg(&mut self, _name: &str, _value: u64) -> Result<()> {
            Err(DebugError::UnsupportedPlatform(
                "Windows write_reg: implementar con SetThreadContext".into(),
            ))
        }

        fn read_mem(&mut self, _addr: u64, _len: usize) -> Result<Vec<u8>> {
            // ReadProcessMemory
            Err(DebugError::UnsupportedPlatform(
                "Windows read_mem: implementar con ReadProcessMemory".into(),
            ))
        }

        fn write_mem(&mut self, _addr: u64, _data: &[u8]) -> Result<()> {
            // WriteProcessMemory + FlushInstructionCache
            Err(DebugError::UnsupportedPlatform(
                "Windows write_mem: implementar con WriteProcessMemory".into(),
            ))
        }

        fn wait(&mut self) -> Result<StopEvent> {
            // WaitForDebugEvent
            Err(DebugError::UnsupportedPlatform(
                "Windows wait: implementar con WaitForDebugEvent".into(),
            ))
        }

        fn kill(&mut self) -> Result<()> {
            // TerminateProcess
            Ok(())
        }
    }
}

// ============================================================================
// macOS Mach exceptions backend (skeleton)
// ============================================================================

#[cfg(target_os = "macos")]
pub mod macos_backend {
    use super::*;
    use std::ptr;

    // En macOS la depuración usa las Mach Exceptions API
    // (task_get_exception_ports / task_set_exception_ports) + el cuerpo de
    // la Mach interface. Una implementación real es ~600 líneas; aquí
    // dejamos un stub compilable.

    pub struct MacosBackend {
        pub pid: Option<u32>,
    }

    impl MacosBackend {
        pub fn new() -> Self {
            Self { pid: None }
        }
    }

    impl Default for MacosBackend {
        fn default() -> Self {
            Self::new()
        }
    }

    impl DebugBackend for MacosBackend {
        fn spawn(&mut self, _path: &str, _args: &[String]) -> Result<u32> {
            Err(DebugError::UnsupportedPlatform(
                "macOS debugger backend: skeleton — implementar con Mach exceptions".into(),
            ))
        }
        fn cont(&mut self) -> Result<()> { Ok(()) }
        fn step(&mut self) -> Result<()> { Ok(()) }
        fn read_regs(&mut self) -> Result<RegSet> { Ok(RegSet::new()) }
        fn write_reg(&mut self, _name: &str, _value: u64) -> Result<()> { Ok(()) }
        fn read_mem(&mut self, _addr: u64, _len: usize) -> Result<Vec<u8>> { Ok(vec![]) }
        fn write_mem(&mut self, _addr: u64, _data: &[u8]) -> Result<()> { Ok(()) }
        fn wait(&mut self) -> Result<StopEvent> { Ok(StopEvent::Exited(0)) }
        fn kill(&mut self) -> Result<()> { Ok(()) }
    }
}

// ============================================================================
// Debugger facade — maneja breakpoints encima del backend
// ============================================================================

/// Debugger de alto nivel: backend ptrace (Linux) + gestión de breakpoints INT3.
pub struct Debugger {
    backend: Box<dyn DebugBackend>,
    breakpoints: BTreeMap<u64, Breakpoint>,
    /// Direcciones golpeadas (para reportar)
    last_hit: Option<u64>,
    pub pid: Option<u32>,
}

impl Debugger {
    pub fn new() -> Self {
        let backend: Box<dyn DebugBackend> = {
            #[cfg(target_os = "linux")]
            {
                Box::new(linux_backend::LinuxBackend::new())
            }
            #[cfg(target_os = "windows")]
            {
                Box::new(windows_backend::WindowsBackend::new())
            }
            #[cfg(target_os = "macos")]
            {
                Box::new(macos_backend::MacosBackend::new())
            }
            #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
            {
                compile_error!("Plataforma no soportada. Falta backend para este OS.")
            }
        };
        Self {
            backend,
            breakpoints: BTreeMap::new(),
            last_hit: None,
            pid: None,
        }
    }

    /// Inicia el programa bajo debug.
    pub fn spawn(&mut self, path: &str, args: &[String]) -> Result<u32> {
        let pid = self.backend.spawn(path, args)?;
        self.pid = Some(pid);
        Ok(pid)
    }

    /// Pone un breakpoint software (INT3) en una dirección.
    pub fn set_breakpoint(&mut self, addr: u64) -> Result<()> {
        if self.breakpoints.contains_key(&addr) {
            return Ok(()); // ya existe
        }
        let word = self.backend.read_mem(addr, 1)?;
        let bp = Breakpoint {
            address: addr,
            original_byte: word[0],
            enabled: true,
            hit: false,
        };
        // escribir 0xCC
        self.backend.write_mem(addr, &[0xCC])?;
        self.breakpoints.insert(addr, bp);
        Ok(())
    }

    /// Elimina un breakpoint.
    pub fn remove_breakpoint(&mut self, addr: u64) -> Result<()> {
        if let Some(bp) = self.breakpoints.remove(&addr) {
            self.backend.write_mem(addr, &[bp.original_byte])?;
        }
        Ok(())
    }

    /// Lista de breakpoints activos.
    pub fn breakpoints(&self) -> Vec<&Breakpoint> {
        self.breakpoints.values().collect()
    }

    /// Continúa hasta el próximo breakpoint/señal.
    pub fn cont(&mut self) -> Result<StopEvent> {
        // si paramos en un breakpoint, restaurar byte y retroceder RIP
        if let Some(addr) = self.last_hit.take() {
            let rip = self.backend.read_regs()?.get("rip").copied().unwrap_or(0);
            if rip == addr + 1 {
                self.backend.write_reg("rip", addr)?;
            }
            let bp = &self.breakpoints[&addr];
            self.backend.write_mem(addr, &[bp.original_byte])?;
            // single-step sobre la instrucción original
            self.backend.step()?;
            let _ = self.backend.wait()?; // consumir el trap del step
            // re-armar el INT3
            self.backend.write_mem(addr, &[0xCC])?;
        }
        self.backend.cont()?;
        let event = self.backend.wait()?;
        if let StopEvent::Trap = event {
            // ¿fue un breakpoint nuestro?
            let rip = self.backend.read_regs()?.get("rip").copied().unwrap_or(0);
            if let Some(bp) = self.breakpoints.get_mut(&(rip - 1)) {
                bp.hit = true;
                self.last_hit = Some(rip - 1);
            }
        }
        Ok(event)
    }

    /// Ejecuta una instrucción (single step).
    pub fn step(&mut self) -> Result<StopEvent> {
        self.backend.step()?;
        self.backend.wait()
    }

    /// Registros actuales del tracee.
    pub fn registers(&mut self) -> Result<RegSet> {
        self.backend.read_regs()
    }

    /// Lee memoria.
    pub fn read_memory(&mut self, addr: u64, len: usize) -> Result<Vec<u8>> {
        self.backend.read_mem(addr, len)
    }

    /// Escribe memoria.
    pub fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        self.backend.write_mem(addr, data)
    }

    /// Desensambla `count` instrucciones desde RIP.
    pub fn disasm_at_rip(&mut self, disasm: &Disassembler, count: usize) -> Result<Vec<Instruction>> {
        let rip = self.backend.read_regs()?.get("rip").copied().unwrap_or(0);
        let code = self.backend.read_mem(rip, count * 15)?;
        let insns = disasm.disassemble(&code, rip)?;
        Ok(insns.into_iter().take(count).collect())
    }

    /// Termina el proceso depurado.
    pub fn kill(&mut self) -> Result<()> {
        self.backend.kill()?;
        self.pid = None;
        Ok(())
    }
}

impl Default for Debugger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debugger_constructs() {
        let d = Debugger::new();
        assert!(d.breakpoints().is_empty());
        assert!(d.pid.is_none());
    }
}
