//! # Bitwise Structuring
//!
//! Convierte un CFG en bloques con alto nivel (if/else/while) usando
//! pattern matching de patrones de CFG estándar:
//!   - if/else (patrón diamante: branch condicional con merge posterior)
//!   - if sin else (branch condicional que salta a un sucesor sin merge)
//!   - while/loop (back-edge)
//!   - do-while (self-loop natural)
//!   - secuencias straight-line
//!
//! Algoritmo: dominadores post-order con pattern recognition.
//! Inspirado en el approach clásico del paper "Structured Programming with
//! goto Statements" (Knuth 1974) y decompiladores como DREAM y fcd.

use bitwise_ir::{EdgeType, IrBlock, IrFunction};

/// Bloque estructurado de alto nivel.
#[derive(Debug, Clone)]
pub enum Structured {
    Sequence(Vec<Structured>),
    If {
        condition: String,
        then_branch: Box<Structured>,
        else_branch: Option<Box<Structured>>,
    },
    While {
        condition: String,
        body: Box<Structured>,
    },
    DoWhile {
        body: Box<Structured>,
        condition: String,
    },
    Loop(Box<Structured>), // while(true) { ... }
    Break,                 // rompe el loop envolvente
    Continue,              // continua el loop envolvente
    Block(Vec<Structured>),
    RawStmt(String), // statement P-Code literal
}

impl Structured {
    pub fn render(&self, indent: usize) -> String {
        let pad = "    ".repeat(indent);
        match self {
            Structured::Sequence(seq) => seq
                .iter()
                .map(|s| s.render(indent))
                .collect::<Vec<_>>()
                .join("\n"),
            Structured::If { condition, then_branch, else_branch } => {
                let mut s = format!("{}if ({}) {{\n", pad, condition);
                s.push_str(&then_branch.render(indent + 1));
                s.push('\n');
                s.push_str(&format!("{}}}", pad));
                if let Some(e) = else_branch {
                    s.push_str(&format!(" else {{\n"));
                    s.push_str(&e.render(indent + 1));
                    s.push('\n');
                    s.push_str(&format!("{}}}", pad));
                }
                s
            }
            Structured::While { condition, body } => {
                let mut s = format!("{}while ({}) {{\n", pad, condition);
                s.push_str(&body.render(indent + 1));
                s.push('\n');
                s.push_str(&format!("{}}}", pad));
                s
            }
            Structured::DoWhile { body, condition } => {
                let mut s = format!("{}do {{\n", pad);
                s.push_str(&body.render(indent + 1));
                s.push('\n');
                s.push_str(&format!("{}}} while ({});", pad, condition));
                s
            }
            Structured::Loop(body) => {
                let mut s = format!("{}loop {{\n", pad);
                s.push_str(&body.render(indent + 1));
                s.push('\n');
                s.push_str(&format!("{}}}", pad));
                s
            }
            Structured::Break => format!("{}break;", pad),
            Structured::Continue => format!("{}continue;", pad),
            Structured::Block(items) => {
                let mut s = format!("{}{{\n", pad);
                for item in items {
                    s.push_str(&item.render(indent + 1));
                    s.push('\n');
                }
                s.push_str(&format!("{}}}", pad));
                s
            }
            Structured::RawStmt(stmt) => format!("{}{};", pad, stmt),
        }
    }
}

// ============================================================================
// CFG → Structured
// ============================================================================

/// Resultado del análisis de dominadores.
#[derive(Default, Clone)]
struct Dominators {
    /// idom[id] = immediate dominator of id
    idom: Vec<Option<usize>>,
}

pub struct Structurer {
    /// bloques del CFG por id
    blocks: Vec<IrBlock>,
    /// id del bloque de entrada
    entry: usize,
    /// dominadores calculados
    dom: Dominators,
    /// successor edges: block_id -> list of (target, edge_type)
    succ: Vec<Vec<(usize, EdgeType)>>,
    /// predecessor edges
    pred: Vec<Vec<usize>>,
}

impl Structurer {
    pub fn new(func: &IrFunction) -> Self {
        let n = func.blocks.len();
        let mut succ: Vec<Vec<(usize, EdgeType)>> = vec![vec![]; n];
        let mut pred: Vec<Vec<usize>> = vec![vec![]; n];
        for (i, b) in func.blocks.iter().enumerate() {
            for (target, edge) in &b.successors {
                let t = *target;
                if t < n {
                    succ[i].push((t, *edge));
                    if !pred[t].contains(&i) {
                        pred[t].push(i);
                    }
                }
            }
        }
        let entry = func.entry_block().unwrap_or(0);

        let mut s = Self {
            blocks: func.blocks.clone(),
            entry,
            dom: Dominators::default(),
            succ,
            pred,
        };
        s.compute_dominators();
        s
    }

    /// Algoritmo de Lengauer-Tarjan simplificado para dominadores.
    /// O(N^2) en el peor caso, pero suficiente para CFGs típicos.
    fn compute_dominators(&mut self) {
        let n = self.blocks.len();
        if n == 0 {
            return;
        }
        let mut idom: Vec<Option<usize>> = vec![None; n];
        idom[self.entry] = Some(self.entry);

        // iterativo: recalcular hasta punto fijo
        let mut changed = true;
        let mut iterations = 0;
        while changed && iterations < 256 {
            changed = false;
            iterations += 1;
            for v in 0..n {
                if v == self.entry {
                    continue;
                }
                let preds = self.pred[v].clone();
                if preds.is_empty() {
                    continue;
                }
                // intersección de dominadores de los preds
                let mut new_idom = None;
                for &p in &preds {
                    if let Some(_) = idom[p] {
                        let mut cur = p;
                        if new_idom.is_none() {
                            new_idom = Some(cur);
                        } else {
                            // caminar cur y new_idom hasta coincidir
                            let mut path_a = std::collections::BTreeSet::new();
                            while cur != new_idom.unwrap() && idom[cur].is_some() && cur != self.entry {
                                path_a.insert(cur);
                                cur = idom[cur].unwrap();
                            }
                            let mut path_b = std::collections::BTreeSet::new();
                            let mut n2 = new_idom.unwrap();
                            while !path_a.contains(&n2) && idom[n2].is_some() && n2 != self.entry {
                                path_b.insert(n2);
                                n2 = idom[n2].unwrap();
                            }
                            new_idom = Some(n2);
                        }
                    }
                }
                if let Some(ni) = new_idom {
                    if idom[v] != Some(ni) {
                        idom[v] = Some(ni);
                        changed = true;
                    }
                }
            }
        }
        self.dom.idom = idom;
    }

    fn dominates(&self, a: usize, b: usize) -> bool {
        // ¿`a` domina a `b`?
        if a == b {
            return true;
        }
        let mut cur = Some(b);
        while let Some(c) = cur {
            if c == a {
                return true;
            }
            cur = self.dom.idom[c];
            if cur == Some(c) {
                break; // llegó a root
            }
        }
        false
    }

    /// Estructura el CFG completo y devuelve la raíz.
    pub fn structure(&self) -> Structured {
        let mut visited = vec![false; self.blocks.len()];
        let result = self.structure_block(self.entry, &mut visited, &mut Vec::new());
        result
    }

    /// Estructura desde un bloque, evitando loops en `ancestors` (block_ids en la pila de loops).
    fn structure_block(
        &self,
        block_id: usize,
        visited: &mut [bool],
        loop_ancestors: &mut Vec<usize>,
    ) -> Structured {
        if block_id >= self.blocks.len() {
            return Structured::Block(vec![]);
        }

        // Si estamos dentro de un loop y este bloque es el header, emitir el cuerpo y break.
        if loop_ancestors.contains(&block_id) {
            return Structured::Break;
        }

        let block = &self.blocks[block_id];
        let succs = &self.succ[block_id];

        // Dead code path
        if visited[block_id] {
            return Structured::Block(vec![]);
        }
        visited[block_id] = true;

        // Caso 1: secuencia simple — emitir el bloque y continuar con el primer sucesor
        // (excepto si tiene control flow no-trivial como rama o back-edge)
        let block_text = self.render_block(block);

        // Caso 2: el bloque es un loop header (tiene back-edge entrante)
        if self.is_loop_header(block_id) {
            return self.structure_loop(block_id, visited, loop_ancestors);
        }

        // Caso 3: hay un back-edge desde este bloque → es un break/continue
        if self.has_back_edge(block_id) {
            return self.structure_with_backedge(block_id, visited, loop_ancestors);
        }

        // Caso 4: dos sucesores → condicional
        if succs.len() == 2 {
            let (s1, e1) = succs[0];
            let (s2, e2) = succs[1];
            return self.structure_if(block_id, s1, e1, s2, e2, visited, loop_ancestors);
        }

        // Caso 5: un sucesor, control lineal
        if succs.len() == 1 {
            let (next, _) = succs[0];
            let inner = self.structure_block(next, visited, loop_ancestors);
            return Structured::Block(vec![Structured::raw_stmts(block_text), inner]);
        }

        // Sin sucesores → bloque terminal
        Structured::Block(vec![Structured::raw_stmts(block_text)])
    }

    fn render_block(&self, b: &IrBlock) -> Vec<String> {
        let mut stmts = Vec::new();
        for inst in &b.instructions {
            stmts.push(format!("{}", inst));
        }
        stmts
    }

    /// ¿`block_id` tiene un back-edge entrante (es decir, algún sucesor lo apunta de vuelta)?
    fn is_loop_header(&self, block_id: usize) -> bool {
        for (succ, _) in &self.succ[block_id] {
            if self.dominates(block_id, *succ) {
                return true;
            }
        }
        false
    }

    /// ¿este bloque tiene un back-edge saliente (vuelve a un dominador)?
    fn has_back_edge(&self, block_id: usize) -> bool {
        for (succ, _) in &self.succ[block_id] {
            if self.dominates(*succ, block_id) {
                return true;
            }
        }
        false
    }

    /// Estructura un loop: `while (cond) { body }` o `do-while`.
    fn structure_loop(
        &self,
        header: usize,
        visited: &mut [bool],
        ancestors: &mut Vec<usize>,
    ) -> Structured {
        let block = &self.blocks[header];
        let succs = &self.succ[header].clone();
        // El header puede tener:
        //  - un solo sucesor que sale del loop (condición al final → do-while)
        //  - dos sucesores: uno sale del loop, el otro es el body (while condicional al principio)
        let (cond_text, body_blocks, exit_block) = if succs.len() == 2 {
            // while (cond) { body }
            let (s1, _e1) = succs[0];
            let (s2, _e2) = succs[1];
            // el que NO está dominado por el header es el body
            let (body, exit) = if self.dominates(header, s1) {
                (s1, s2)
            } else {
                (s2, s1)
            };
            let cond = format!("cond (block {:#x})", self.blocks[header].start_address);
            (cond, vec![body], exit)
        } else if !succs.is_empty() {
            // do-while: header → body → back to header
            let (body, _) = succs[0];
            let cond = format!("true (block {:#x})", self.blocks[header].start_address);
            (cond, vec![body], usize::MAX)
        } else {
            return Structured::Block(vec![]);
        };

        ancestors.push(header);
        let mut body_items = vec![Structured::raw_stmts(self.render_block(block))];
        for b in body_blocks {
            if !ancestors.contains(&b) {
                body_items.push(self.structure_block(b, visited, ancestors));
            }
        }
        ancestors.pop();

        if succs.len() == 2 {
            // es un while
            Structured::While {
                condition: cond_text,
                body: Box::new(Structured::Block(body_items)),
            }
        } else {
            // do-while o loop infinito
            Structured::DoWhile {
                body: Box::new(Structured::Block(body_items)),
                condition: cond_text,
            }
        }
    }

    /// Estructura un bloque cuyo flujo sale (back-edge) → se traduce a break/continue.
    fn structure_with_backedge(
        &self,
        block_id: usize,
        visited: &mut [bool],
        ancestors: &mut Vec<usize>,
    ) -> Structured {
        let block = &self.blocks[block_id];
        let mut items: Vec<Structured> = vec![Structured::raw_stmts(self.render_block(block))];
        for (succ, _) in &self.succ[block_id] {
            // saltar el back-edge (break) — no seguir
            if self.dominates(*succ, block_id) {
                items.push(Structured::Break);
            } else if !visited[*succ] && !ancestors.contains(succ) {
                items.push(self.structure_block(*succ, visited, ancestors));
            }
        }
        Structured::Block(items)
    }

    /// Patrón if/else: el bloque tiene 2 sucesores; el que NO es dominado es el else, el otro es el then.
    fn structure_if(
        &self,
        block_id: usize,
        s1: usize,
        _e1: EdgeType,
        s2: usize,
        _e2: EdgeType,
        visited: &mut [bool],
        ancestors: &mut Vec<usize>,
    ) -> Structured {
        let block = &self.blocks[block_id];
        let cond = format!("cond (block {:#x})", block.start_address);

        let then_block = if self.dominates(block_id, s1) { s1 } else { s2 };
        let else_block = if then_block == s1 { s2 } else { s1 };

        let mut head = vec![Structured::raw_stmts(self.render_block(block))];

        // Buscar el merge point (post-dominador común)
        let merge = self.find_merge(then_block, else_block);

        let then_struct = self.structure_branch(then_block, merge, visited, ancestors);
        let mut else_struct: Option<Box<Structured>> = None;
        if else_block != merge {
            else_struct = Some(Box::new(self.structure_branch(
                else_block, merge, visited, ancestors,
            )));
        }

        // agregar el bloque de merge
        let if_node = Structured::If {
            condition: cond,
            then_branch: Box::new(then_struct),
            else_branch: else_struct,
        };
        head.push(if_node);
        if merge < self.blocks.len() && !visited[merge] && !ancestors.contains(&merge) {
            head.push(self.structure_block(merge, visited, ancestors));
        }
        Structured::Block(head)
    }

    /// Encuentra el merge point (post-dominador común) de dos ramas.
    fn find_merge(&self, a: usize, b: usize) -> usize {
        // BFS simple: recoger todos los alcanzables de a, luego ver cuál de los ancestros
        // de b es el más cercano que también es alcanzable desde a.
        let mut reach_a: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
        let mut q = std::collections::VecDeque::new();
        q.push_back(a);
        while let Some(x) = q.pop_front() {
            if reach_a.insert(x) {
                for (s, _) in &self.succ[x] {
                    if !reach_a.contains(s) {
                        q.push_back(*s);
                    }
                }
            }
        }
        // BFS desde b y devolver el primer nodo que también está en reach_a
        let mut visited: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
        let mut q = std::collections::VecDeque::new();
        q.push_back(b);
        while let Some(x) = q.pop_front() {
            if visited.insert(x) {
                if reach_a.contains(&x) {
                    return x;
                }
                for (s, _) in &self.succ[x] {
                    if !visited.contains(s) {
                        q.push_back(*s);
                    }
                }
            }
        }
        usize::MAX // sin merge: branches terminan en return
    }

    /// Estructura una rama knowing que termina en `target` o sale antes.
    fn structure_branch(
        &self,
        start: usize,
        target: usize,
        visited: &mut [bool],
        ancestors: &mut Vec<usize>,
    ) -> Structured {
        if start == target || start == usize::MAX {
            return Structured::Block(vec![]);
        }
        if ancestors.contains(&start) {
            return Structured::Break;
        }
        // Si el bloque ya fue visitado, solo emitir el texto para no perder info
        let block = &self.blocks[start];
        let mut items: Vec<Structured> = vec![Structured::raw_stmts(self.render_block(block))];
        visited[start] = true;
        for (succ, _) in &self.succ[start] {
            if *succ == target {
                continue;
            }
            if !visited[*succ] && !ancestors.contains(succ) {
                items.push(self.structure_block(*succ, visited, ancestors));
            }
        }
        Structured::Block(items)
    }
}

impl Structured {
    fn raw_stmts(stmts: Vec<String>) -> Structured {
        Structured::Block(stmts.into_iter().map(Structured::raw_stmt).collect())
    }

    fn raw_stmt(s: String) -> Structured {
        // Wrap a single statement into a Block with one item
        Structured::Block(vec![Structured::RawStmt(s)])
    }
}

// Necesitamos una variante RawStmt para preservar statements sin processing
impl Structured {
    #[doc(hidden)]
    pub fn new_raw(s: String) -> Structured {
        Structured::Block(vec![Structured::RawStmt(s)])
    }
}

impl Structured {
    pub fn render_full(&self) -> String {
        self.render(0)
    }
}

// Añadimos variante RawStmt al enum:
// (pequeño workaround porque Rust no permite agregar variantes en un parche
//  sin refactor — ver archivo `lib.rs` decomp donde se hace la emisión)
