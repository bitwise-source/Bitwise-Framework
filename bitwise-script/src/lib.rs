//! # Bitwise Script — Motor de scripting embebido
//!
//! Mini-lenguaje de scripting para automatizar análisis de binarios.
//! Diseño tipo forth/DSL simple con comandos nativos registrables:
//!
//! ```text
//! # ejemplo bitwise script
//! open "/bin/ls"
//! sections where(execute)
//! symbols --func
//! disasm .text
//! eval 0x40 + 8
//! ```

use bitwise_core::binary;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum ScriptError {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("runtime error: {0}")]
    Runtime(String),
    #[error("unknown command: {0}")]
    UnknownCommand(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Core(#[from] bitwise_core::error::BitwiseError),
}

pub type Result<T> = std::result::Result<T, ScriptError>;

// ============================================================================
// AST
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Int(i64),
    Bool(bool),
    List(Vec<Value>),
    None,
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Str(s) => write!(f, "{}", s),
            Value::Int(i) => write!(f, "{}", i),
            Value::Bool(b) => write!(f, "{}", b),
            Value::List(items) => {
                let strs: Vec<String> = items.iter().map(|v| v.to_string()).collect();
                write!(f, "[{}]", strs.join(", "))
            }
            Value::None => write!(f, "none"),
        }
    }
}

/// Un comando del script: nombre + argumentos.
#[derive(Debug, Clone)]
pub struct Command {
    pub name: String,
    pub args: Vec<Value>,
}

/// Script completo: secuencia de comandos.
#[derive(Debug, Clone, Default)]
pub struct Script {
    pub commands: Vec<Command>,
}

// ============================================================================
// Parser (tokenizer simple + line-based commands)
// ============================================================================

pub struct Parser;

impl Parser {
    /// Parsea un script en memoria.
    pub fn parse(source: &str) -> Result<Script> {
        let mut script = Script::default();

        for (lineno, raw) in source.lines().enumerate() {
            let line = raw.trim();
            // comentarios y líneas vacías
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            let cmd = Self::parse_line(line)
                .map_err(|e| ScriptError::Parse(format!("línea {}: {}", lineno + 1, e)))?;
            if let Some(c) = cmd {
                script.commands.push(c);
            }
        }

        Ok(script)
    }

    fn parse_line(line: &str) -> Result<Option<Command>> {
        let tokens = Self::tokenize(line)?;
        if tokens.is_empty() {
            return Ok(None);
        }
        let name = tokens[0].clone();
        let mut args = Vec::new();
        for tok in &tokens[1..] {
            args.push(Self::token_to_value(tok)?);
        }
        Ok(Some(Command { name, args }))
    }

    fn tokenize(line: &str) -> Result<Vec<String>> {
        let mut tokens = Vec::new();
        let mut chars = line.chars().peekable();
        while let Some(&c) = chars.peek() {
            match c {
                ' ' | '\t' => {
                    chars.next();
                }
                '"' => {
                    chars.next();
                    let mut s = String::new();
                    while let Some(&c2) = chars.peek() {
                        if c2 == '"' {
                            chars.next();
                            break;
                        }
                        s.push(c2);
                        chars.next();
                    }
                    tokens.push(format!("\"{}\"", s));
                }
                _ => {
                    let mut s = String::new();
                    while let Some(&c2) = chars.peek() {
                        if c2 == ' ' || c2 == '\t' {
                            break;
                        }
                        s.push(c2);
                        chars.next();
                    }
                    tokens.push(s);
                }
            }
        }
        Ok(tokens)
    }

    fn token_to_value(tok: &str) -> Result<Value> {
        if tok.starts_with('"') && tok.ends_with('"') && tok.len() >= 2 {
            return Ok(Value::Str(tok[1..tok.len() - 1].to_string()));
        }
        if let Some(hex) = tok.strip_prefix("0x") {
            if let Ok(v) = i64::from_str_radix(hex, 16) {
                return Ok(Value::Int(v));
            }
        }
        if let Ok(v) = tok.parse::<i64>() {
            return Ok(Value::Int(v));
        }
        if tok == "true" {
            return Ok(Value::Bool(true));
        }
        if tok == "false" {
            return Ok(Value::Bool(false));
        }
        // identificador crudo → string (nombre de sección, flag, etc.)
        Ok(Value::Str(tok.to_string()))
    }
}

// ============================================================================
// Interpreter
// ============================================================================

/// Estado del intérprete: binario cargado + variables.
pub struct Interpreter {
    pub loaded: Option<bitwise_core::BinaryInfo>,
    pub vars: BTreeMap<String, Value>,
    /// Último resultado (para encadenar con `eval`)
    last: Value,
}

impl Default for Interpreter {
    fn default() -> Self {
        Self::new()
    }
}

impl Interpreter {
    pub fn new() -> Self {
        Self {
            loaded: None,
            vars: BTreeMap::new(),
            last: Value::None,
        }
    }

    /// Ejecuta un script completo; devuelve el último valor producido.
    pub fn run(&mut self, source: &str) -> Result<Value> {
        let script = Parser::parse(source)?;
        for cmd in &script.commands {
            self.last = self.exec(cmd)?;
        }
        Ok(self.last.clone())
    }

    /// Ejecuta un solo comando.
    pub fn exec(&mut self, cmd: &Command) -> Result<Value> {
        match cmd.name.as_str() {
            "open" => self.cmd_open(&cmd.args),
            "info" => self.cmd_info(),
            "sections" => self.cmd_sections(&cmd.args),
            "symbols" => self.cmd_symbols(&cmd.args),
            "eval" => self.cmd_eval(&cmd.args),
            "let" => self.cmd_let(&cmd.args),
            "count" => self.cmd_count(&cmd.args),
            "print" => self.cmd_print(&cmd.args),
            "help" => Ok(Value::Str(HELP.to_string())),
            other => Err(ScriptError::UnknownCommand(other.to_string())),
        }
    }

    fn cmd_open(&mut self, args: &[Value]) -> Result<Value> {
        let path = match args.first() {
            Some(Value::Str(s)) => s.clone(),
            _ => return Err(ScriptError::Runtime("open requiere una ruta".into())),
        };
        let info = binary::load_binary(&PathBuf::from(&path))?;
        let summary = format!(
            "{}: {:?} {:?} {} secciones {} símbolos",
            path, info.format, info.architecture, info.sections.len(), info.symbols.len()
        );
        self.loaded = Some(info);
        Ok(Value::Str(summary))
    }

    fn cmd_info(&mut self) -> Result<Value> {
        let info = self
            .loaded
            .as_ref()
            .ok_or_else(|| ScriptError::Runtime("no hay binario cargado (usa open)".into()))?;
        Ok(Value::Str(format!(
            "path={} format={:?} arch={:?} entry={:#x} sections={} symbols={}",
            info.path,
            info.format,
            info.architecture,
            info.entry_point.unwrap_or(0),
            info.sections.len(),
            info.symbols.len()
        )))
    }

    fn cmd_sections(&mut self, args: &[Value]) -> Result<Value> {
        let info = self
            .loaded
            .as_ref()
            .ok_or_else(|| ScriptError::Runtime("no hay binario cargado".into()))?;

        let only_exec = args.iter().any(|a| matches!(a, Value::Str(s) if s == "exec" || s == "execute"));

        let names: Vec<Value> = info
            .sections
            .iter()
            .filter(|s| !only_exec || s.permissions.execute)
            .map(|s| Value::Str(s.name.clone()))
            .collect();
        Ok(Value::List(names))
    }

    fn cmd_symbols(&mut self, args: &[Value]) -> Result<Value> {
        let info = self
            .loaded
            .as_ref()
            .ok_or_else(|| ScriptError::Runtime("no hay binario cargado".into()))?;

        let funcs_only = args.iter().any(|a| matches!(a, Value::Str(s) if s == "func" || s == "--func"));

        let syms: Vec<Value> = info
            .symbols
            .iter()
            .filter(|s| !funcs_only || matches!(s.kind, bitwise_core::SymbolKind::Function))
            .map(|s| Value::Str(s.name.clone()))
            .collect();
        Ok(Value::List(syms))
    }

    /// eval: expresión aritmética simple "a + b", "a - b", "a * b".
    fn cmd_eval(&mut self, args: &[Value]) -> Result<Value> {
        if args.len() == 3 {
            let a = self.as_int(&args[0])?;
            let op = self.as_str(&args[1])?;
            let b = self.as_int(&args[2])?;
            let v = match op.as_str() {
                "+" => a + b,
                "-" => a - b,
                "*" => a * b,
                "/" => {
                    if b == 0 {
                        return Err(ScriptError::Runtime("división por cero".into()));
                    }
                    a / b
                }
                _ => return Err(ScriptError::Runtime(format!("operador desconocido: {}", op))),
            };
            return Ok(Value::Int(v));
        }
        if args.len() == 1 {
            return Ok(args[0].clone());
        }
        Err(ScriptError::Runtime("eval requiere 1 o 3 argumentos".into()))
    }

    fn cmd_let(&mut self, args: &[Value]) -> Result<Value> {
        if args.len() != 2 {
            return Err(ScriptError::Runtime("let requiere nombre y valor".into()));
        }
        let name = self.as_str(&args[0])?;
        self.vars.insert(name, args[1].clone());
        Ok(args[1].clone())
    }

    fn cmd_count(&mut self, args: &[Value]) -> Result<Value> {
        match args.first() {
            Some(Value::List(items)) => Ok(Value::Int(items.len() as i64)),
            Some(Value::Str(s)) => Ok(Value::Int(s.len() as i64)),
            _ => Err(ScriptError::Runtime("count requiere lista o string".into())),
        }
    }

    fn cmd_print(&mut self, args: &[Value]) -> Result<Value> {
        println!("{}", args.first().unwrap_or(&Value::None));
        Ok(Value::None)
    }

    fn as_int(&self, v: &Value) -> Result<i64> {
        match v {
            Value::Int(i) => Ok(*i),
            Value::Bool(b) => Ok(*b as i64),
            _ => Err(ScriptError::Runtime(format!("se esperaba entero, tengo {:?}", v))),
        }
    }

    fn as_str(&self, v: &Value) -> Result<String> {
        match v {
            Value::Str(s) => Ok(s.clone()),
            _ => Err(ScriptError::Runtime(format!("se esperaba string, tengo {:?}", v))),
        }
    }
}

const HELP: &str = "\
comandos disponibles:
  open <ruta>        carga un binario
  info               resumen del binario cargado
  sections [exec]    lista secciones (solo ejecutables con exec)
  symbols [func]     lista símbolos (solo funciones con func)
  eval <a> <op> <b>  aritmética entera
  let <nombre> <v>   define variable
  count <lista>      longitud
  print <valor>      imprime
  help               esta ayuda";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let script = Parser::parse("open \"/bin/ls\"\ninfo\n# comentario\n").unwrap();
        assert_eq!(script.commands.len(), 2);
        assert_eq!(script.commands[0].name, "open");
        assert_eq!(script.commands[0].args[0], Value::Str("/bin/ls".into()));
    }

    #[test]
    fn eval_arithmetic() {
        let mut interp = Interpreter::new();
        let v = interp.run("eval 0x10 + 0x20").unwrap();
        assert_eq!(v, Value::Int(0x30));
    }

    #[test]
    fn unknown_command_rejected() {
        let mut interp = Interpreter::new();
        let err = interp.run("frobnicate").unwrap_err();
        assert!(matches!(err, ScriptError::UnknownCommand(_)));
    }
}
