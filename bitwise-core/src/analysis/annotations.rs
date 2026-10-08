//! # Annotations & proyecto
//!
//! Capa de renombrado y anotación persistente. Permite:
//!  - renombrar funciones (`0x4da4 → "main"`)
//!  - renombrar variables/temps (`t1000 → "filename"`)
//!  - forzar un tipo (`0x1000 → struct Widget`)
//!  - añadir comentarios a una dirección
//!
//! Todo se guarda en un archivo de proyecto JSON (`<bin>.bitwise.json`) para
//! re-aplicarse en cada decompilación. Es la base de un decompilador
//! interactivo: cualquier cliente (TUI, MCP, CLI) carga el mismo proyecto.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Project {
    /// dirección (hex string) → nombre de función
    pub functions: BTreeMap<String, String>,
    /// temp id → nombre de variable
    pub variables: BTreeMap<String, String>,
    /// temp id → tipo forzado (ej "void*", "struct Widget")
    pub types: BTreeMap<String, String>,
    /// dirección (hex) → comentario
    pub comments: BTreeMap<String, String>,
}

impl Project {
    pub fn new() -> Self {
        Self::default()
    }

    /// Carga un proyecto desde `<bin>.bitwise.json`; si no existe, vacío.
    pub fn load_for(binary_path: &Path) -> Self {
        let proj_path = project_path_for(binary_path);
        match std::fs::read_to_string(&proj_path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
            Err(_) => Project::new(),
        }
    }

    /// Guarda el proyecto en disco.
    pub fn save_for(&self, binary_path: &Path) -> std::io::Result<()> {
        let proj_path = project_path_for(binary_path);
        let text = serde_json::to_string_pretty(self)?;
        std::fs::write(proj_path, text)
    }

    /// Renombra una función (dirección en hex string).
    pub fn rename_function(&mut self, addr: u64, name: &str) {
        self.functions.insert(format!("{:x}", addr), name.to_string());
    }

    pub fn function_name(&self, addr: u64) -> Option<&str> {
        self.functions.get(&format!("{:x}", addr)).map(|s| s.as_str())
    }

    /// Renombra una variable/temp.
    pub fn rename_variable(&mut self, temp_id: u64, name: &str) {
        self.variables.insert(format!("t{}", temp_id), name.to_string());
    }

    pub fn variable_name(&self, temp_id: u64) -> Option<&str> {
        self.variables.get(&format!("t{}", temp_id)).map(|s| s.as_str())
    }

    /// Fuerza un tipo.
    pub fn set_type(&mut self, temp_id: u64, ty: &str) {
        self.types.insert(format!("t{}", temp_id), ty.to_string());
    }

    pub fn forced_type(&self, temp_id: u64) -> Option<&str> {
        self.types.get(&format!("t{}", temp_id)).map(|s| s.as_str())
    }

    /// Añade un comentario a una dirección.
    pub fn add_comment(&mut self, addr: u64, comment: &str) {
        self.comments.insert(format!("{:x}", addr), comment.to_string());
    }

    pub fn comment(&self, addr: u64) -> Option<&str> {
        self.comments.get(&format!("{:x}", addr)).map(|s| s.as_str())
    }
}

fn project_path_for(binary_path: &Path) -> PathBuf {
    let mut p = binary_path.to_path_buf();
    let mut name = p
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| "binary".to_string());
    name.push_str(".bitwise.json");
    p.set_file_name(name);
    p
}

/// Builder para project path (test helper).
pub fn project_path(binary_path: &str) -> String {
    project_path_for(Path::new(binary_path))
        .to_string_lossy()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rename_function_roundtrip() {
        let mut p = Project::new();
        p.rename_function(0x4da4, "main");
        assert_eq!(p.function_name(0x4da4), Some("main"));
    }

    #[test]
    fn save_and_load() {
        let dir = std::env::temp_dir().join("bitwise_test_proj");
        let _ = std::fs::create_dir_all(&dir);
        let bin = dir.join("testbin");
        std::fs::write(&bin, b"x").unwrap();

        let mut p = Project::new();
        p.rename_function(0x1000, "decrypt");
        p.rename_variable(5, "key");
        p.save_for(&bin).unwrap();

        let loaded = Project::load_for(&bin);
        assert_eq!(loaded.function_name(0x1000), Some("decrypt"));
        assert_eq!(loaded.variable_name(5), Some("key"));

        let _ = std::fs::remove_file(&bin);
        let _ = std::fs::remove_file(project_path_for(&bin));
    }
}