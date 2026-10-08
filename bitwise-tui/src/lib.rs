//! # Bitwise TUI — Terminal User Interface
//!
//! Interfaz interactiva de terminal para explorar binarios: vistas de
//! desensamblado, hex dump, símbolos y secciones con navegación por teclado.
//!
//! Teclas: ↑/↓ navegar · 1-4 cambiar vista · / buscar · q salir

use bitwise_core::binary;
use bitwise_core::{BinaryInfo, Section, Symbol};
use bitwise_disasm::{format_instructions, Disassembler};
use std::io::{self, Write};

pub mod view;
pub mod hexdump;
pub mod cfg_dot;

pub use view::ViewMode;

use bitwise_core::analysis::annotations::Project;

/// Estado global de la sesión TUI.
pub struct TuiSession {
    pub info: BinaryInfo,
    pub disasm: Option<Disassembler>,
    pub instructions: Vec<bitwise_core::arch::Instruction>,
    /// Índice de línea seleccionada en la vista activa
    pub cursor: usize,
    /// Scroll offset del render
    pub scroll: usize,
    pub mode: ViewMode,
    pub query: String,
    pub running: bool,
    /// Texto de estado (mensajes al usuario)
    pub status: String,
    /// Funciones detectadas (call-graph + símbolos + prólogos)
    pub functions: Vec<u64>,
    /// Proyecto de annotations persistente
    pub project: Project,
    /// Path del binario (para guardar el proyecto)
    pub bin_path: std::path::PathBuf,
    /// Última decompilación mostrada (vista decomp)
    pub last_decomp: String,
}

impl TuiSession {
    /// Carga el binario y desensambla las secciones ejecutables.
    pub fn load(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let info = binary::load_binary(path)?;

        let (disasm, instructions) = match Disassembler::from_binary(&info) {
            Ok(d) => {
                let insns = d.disassemble_binary(&info).unwrap_or_default();
                (Some(d), insns)
            }
            Err(_) => (None, Vec::new()),
        };

        let functions = bitwise_core::analysis::detect_functions(&instructions, &info.symbols);
        let project = Project::load_for(path);

        Ok(Self {
            info,
            disasm,
            instructions,
            cursor: 0,
            scroll: 0,
            mode: ViewMode::Disasm,
            query: String::new(),
            running: false,
            status: String::new(),
            functions,
            project,
            bin_path: path.to_path_buf(),
            last_decomp: String::new(),
        })
    }

    /// Número de líneas de la vista activa.
    pub fn line_count(&self) -> usize {
        match self.mode {
            ViewMode::Disasm => self.instructions.len(),
            ViewMode::Symbols => self.info.symbols.len(),
            ViewMode::Sections => self.info.sections.len(),
            ViewMode::Functions => self.functions.len(),
            ViewMode::Decomp => self.last_decomp.lines().count(),
            ViewMode::Help => 1,
        }
    }

    /// Avanza el cursor ajustando el scroll.
    pub fn move_down(&mut self, term_height: usize) {
        let max = self.line_count().saturating_sub(1);
        if self.cursor < max {
            self.cursor += 1;
        }
        let visible = term_height.saturating_sub(4); // header + status + bordes
        if self.cursor >= self.scroll + visible {
            self.scroll = self.cursor + 1 - visible;
        }
    }

    pub fn move_up(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
        if self.cursor < self.scroll {
            self.scroll = self.cursor;
        }
    }

    /// Filtra símbolos según la query activa (por nombre, case-insensitive).
    pub fn filtered_symbols(&self) -> Vec<&Symbol> {
        if self.query.is_empty() {
            return self.info.symbols.iter().collect();
        }
        let q = self.query.to_lowercase();
        self.info
            .symbols
            .iter()
            .filter(|s| s.name.to_lowercase().contains(&q))
            .collect()
    }

    /// Genera el contenido textual de la vista activa.
    pub fn render_lines(&self, height: usize) -> Vec<String> {
        match self.mode {
            ViewMode::Disasm => {
                let end = (self.scroll + height).min(self.instructions.len());
                let slice = &self.instructions[self.scroll.min(self.instructions.len())..end];
                let text = format_instructions(slice, true);
                text.lines().map(|l| l.to_string()).collect()
            }
            ViewMode::Symbols => {
                let syms = self.filtered_symbols();
                let end = (self.scroll + height).min(syms.len());
                syms[self.scroll.min(syms.len())..end]
                    .iter()
                    .map(|s| format!("  {:#018x}  {:6}  {:8}  {}", s.address, s.size, kind_str(s), s.name))
                    .collect()
            }
            ViewMode::Sections => self.info.sections[self.scroll.min(self.info.sections.len())..]
                .iter()
                .take(height)
                .map(section_line)
                .collect(),
            ViewMode::Functions => {
                let end = (self.scroll + height).min(self.functions.len());
                self.functions[self.scroll.min(self.functions.len())..end]
                    .iter()
                    .map(|&addr| {
                        let name = self
                            .project
                            .function_name(addr)
                            .map(|s| s.to_string())
                            .or_else(|| {
                                self.info
                                    .symbols
                                    .iter()
                                    .find(|s| s.address == addr)
                                    .map(|s| s.name.clone())
                            })
                            .unwrap_or_else(|| format!("func_{:x}", addr));
                        format!("  {:#018x}  {}", addr, name)
                    })
                    .collect()
            }
            ViewMode::Decomp => {
                let lines: Vec<&str> = self.last_decomp.lines().collect();
                let end = (self.scroll + height).min(lines.len());
                lines[self.scroll.min(lines.len())..end]
                    .iter()
                    .map(|l| l.to_string())
                    .collect()
            }
            ViewMode::Help => crate::view::HELP_TEXT.lines().map(|l| l.to_string()).collect(),
        }
    }

    /// Dirección de la función bajo el cursor (vista Functions).
    pub fn current_function(&self) -> Option<u64> {
        if self.mode != ViewMode::Functions {
            return None;
        }
        self.functions.get(self.cursor).copied()
    }

    /// Renombra la función bajo el cursor y guarda el proyecto.
    pub fn rename_current_function(&mut self, new_name: &str) -> bool {
        if let Some(addr) = self.current_function() {
            self.project.rename_function(addr, new_name);
            let saved = self.project.save_for(&self.bin_path).is_ok();
            self.status = if saved {
                format!("renamed {:#x} → {}", addr, new_name)
            } else {
                format!("renamed (pero falló el guardado) {:#x} → {}", addr, new_name)
            };
            true
        } else {
            self.status = "r solo funciona en la vista de funciones (tecla 5)".into();
            false
        }
    }

    /// Decompila la función bajo el cursor y cambia a la vista Decomp.
    pub fn decompile_current_function(&mut self) -> bool {
        let Some(addr) = self.current_function() else {
            self.status = "d solo funciona en la vista de funciones (tecla 5)".into();
            return false;
        };

        // slicing de la función
        let mut sorted = self.instructions.clone();
        sorted.sort_by_key(|i| i.address);
        let next_start = self
            .functions
            .iter()
            .filter(|&&a| a > addr)
            .min()
            .copied()
            .unwrap_or(u64::MAX);

        let func_insns: Vec<_> = sorted
            .iter()
            .filter(|i| i.address >= addr && i.address < next_start)
            .cloned()
            .collect();

        if func_insns.is_empty() {
            self.status = format!("sin instrucciones en {:#x}", addr);
            return false;
        }

        let mut lifter = bitwise_lift::Lifter::new(bitwise_lift::RegisterMap::x86_64());
        let raw = lifter.lift_all(&func_insns);
        let pcode = bitwise_decomp::optimize(&raw);
        let blocks = bitwise_lift::Lifter::build_blocks(&pcode);

        let name = self
            .project
            .function_name(addr)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("func_{:x}", addr));

        let mut ir_func = bitwise_ir::IrFunction::new(&name, addr);
        ir_func.blocks = blocks;

        let mut decompiler = bitwise_decomp::Decompiler::new();
        self.last_decomp = decompiler.decompile(&ir_func);
        self.mode = ViewMode::Decomp;
        self.cursor = 0;
        self.scroll = 0;
        true
    }
}

fn kind_str(s: &Symbol) -> &'static str {
    use bitwise_core::SymbolKind::*;
    match s.kind {
        Function => "FUNC",
        Object => "OBJ",
        Section => "SECT",
        File => "FILE",
        Unknown => "?",
    }
}

fn section_line(sec: &Section) -> String {
    let perms = format!(
        "{}{}{}",
        if sec.permissions.read { "r" } else { "-" },
        if sec.permissions.write { "w" } else { "-" },
        if sec.permissions.execute { "x" } else { "-" }
    );
    format!(
        "  {:24}  {:#018x}  {:10}  {}",
        sec.name, sec.virtual_address, sec.virtual_size, perms
    )
}

/// Render simple sin dependencias de pantalla completa: imprime y lee teclas.
/// Útil como fallback y para tests.
pub fn render_snapshot(session: &TuiSession, height: usize) -> String {
    let mut out = String::new();
    let title = format!(
        "bitwise — {} — {:?}/{:?}",
        session.info.path,
        session.info.format,
        session.info.architecture
    );
    out.push_str(&format!("{}\r\n{}\r\n", title, "─".repeat(title.len().min(80))));
    for line in session.render_lines(height) {
        out.push_str(&line);
        out.push_str("\r\n");
    }
    out
}

/// Loop principal (raw mode vía crossterm).
pub fn run(session: &mut TuiSession) -> io::Result<()> {
    use crossterm::event::{Event, KeyCode, KeyEvent};
    use crossterm::{execute, terminal};

    let mut stdout = io::stdout();
    terminal::enable_raw_mode()?;
    execute!(stdout, terminal::EnterAlternateScreen)?;
    session.running = true;

    let (_, term_h) = terminal::size()?;
    let mut term_h = term_h as usize;

    while session.running {
        let (_, h) = terminal::size().unwrap_or((80, 24));
        term_h = h as usize;
        redraw(session, term_h, &mut stdout)?;

        if let Event::Key(key) = crossterm::event::read()? {
            if key.kind == crossterm::event::KeyEventKind::Press {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => session.running = false,
                    KeyCode::Down | KeyCode::Char('j') => session.move_down(term_h),
                    KeyCode::Up | KeyCode::Char('k') => session.move_up(),
                    KeyCode::Char('1') => { session.mode = ViewMode::Disasm; session.cursor = 0; session.scroll = 0; }
                    KeyCode::Char('2') => { session.mode = ViewMode::Symbols; session.cursor = 0; session.scroll = 0; }
                    KeyCode::Char('3') => { session.mode = ViewMode::Sections; session.cursor = 0; session.scroll = 0; }
                    KeyCode::Char('4') => { session.mode = ViewMode::Help; }
                    KeyCode::Char('5') => { session.mode = ViewMode::Functions; session.cursor = 0; session.scroll = 0; session.status.clear(); }
                    KeyCode::Char('6') => { session.mode = ViewMode::Decomp; session.cursor = 0; session.scroll = 0; }
                    KeyCode::Char('r') => {
                        session.status = "renombrar: (escribe nombre y Enter, Esc cancela)".into();
                        redraw(session, term_h, &mut stdout)?;
                        let name = read_line_raw_at(&mut stdout, "rename: ")?;
                        session.status.clear();
                        if !name.is_empty() {
                            session.rename_current_function(&name);
                        }
                    }
                    KeyCode::Char('d') => {
                        session.decompile_current_function();
                    }
                    KeyCode::Char('/') => {
                        // búsqueda simple: leer línea desde stdin crudo es complejo;
                        // usamos status para indicar el modo y capturamos caracteres
                        session.status = "buscar: (escribe y Enter, Esc cancela)".into();
                        let q = read_line_raw(&mut stdout)?;
                        session.query = q;
                        session.status.clear();
                        session.cursor = 0;
                        session.scroll = 0;
                    }
                    _ => {}
                }
            }
        }
    }

    execute!(stdout, terminal::LeaveAlternateScreen)?;
    terminal::disable_raw_mode()?;
    Ok(())
}

fn redraw(session: &TuiSession, height: usize, stdout: &mut io::Stdout) -> io::Result<()> {
    use crossterm::cursor::MoveTo;
    use crossterm::style::Print;
    use crossterm::queue;

    queue!(stdout, MoveTo(0, 0))?;

    let title = format!(
        " bitwise │ {} │ {:?} {:?} │ [1]disasm [2]sym [3]sect [5]funcs [6]decomp [4]help [r]ename [d]ecomp [/]search [q]uit ",
        session.info.path,
        session.info.format,
        session.info.architecture
    );
    queue!(stdout, Print(title))?;
    queue!(stdout, MoveTo(0, 1))?;
    queue!(stdout, Print("─".repeat(100)))?;

    let body_h = height.saturating_sub(3);
    for (i, line) in session.render_lines(body_h).into_iter().enumerate() {
        queue!(stdout, MoveTo(0, (i + 2) as u16))?;
        let marker = if i + session.scroll == session.cursor { ">" } else { " " };
        let truncated: String = line.chars().take(120).collect();
        queue!(stdout, Print(format!("{}{}", marker, truncated)))?;
    }

    let status = if session.status.is_empty() {
        format!(
            " [{} lines] cursor={} scroll={} query='{}'",
            session.line_count(),
            session.cursor,
            session.scroll,
            session.query
        )
    } else {
        format!(" {}", session.status)
    };
    queue!(stdout, MoveTo(0, (height.saturating_sub(1)) as u16))?;
    queue!(stdout, Print(status))?;

    stdout.flush()
}

/// Lee una línea caracter a caracter en raw mode (para la búsqueda '/').
fn read_line_raw(stdout: &mut io::Stdout) -> io::Result<String> {
    read_line_raw_at(stdout, "buscar: ")
}

/// Lee una línea con prompt configurable (búsqueda y renombrado).
fn read_line_raw_at(stdout: &mut io::Stdout, prompt: &str) -> io::Result<String> {
    use crossterm::event::{Event, KeyCode};
    let mut buf = String::new();
    loop {
        if let Event::Key(key) = crossterm::event::read()? {
            match key.code {
                KeyCode::Enter => break,
                KeyCode::Esc => {
                    buf.clear();
                    break;
                }
                KeyCode::Backspace => {
                    buf.pop();
                }
                KeyCode::Char(c) => buf.push(c),
                _ => {}
            }
            use crossterm::cursor::MoveTo;
            use crossterm::style::Print;
            use crossterm::queue;
            queue!(stdout, MoveTo(0, 23), Print(format!("{}{}  ", prompt, buf)))?;
            stdout.flush()?;
        }
    }
    Ok(buf)
}
