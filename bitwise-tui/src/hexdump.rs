//! Hex dump con offset, hex y ASCII — estilo `xxd`.

/// Genera un hex dump de 16 bytes por línea.
pub fn hexdump(data: &[u8], base_address: u64) -> String {
    let mut out = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        let addr = base_address + (i * 16) as u64;
        let hex: Vec<String> = chunk.iter().map(|b| format!("{:02x}", b)).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    (b as char).to_string()
                } else {
                    ".".to_string()
                }
            })
            .collect();
        // padding para líneas cortas
        let pad = "  ".repeat(16 - chunk.len());
        out.push_str(&format!("{:016x}  {}{}  |{}|\n", addr, hex.join(" "), pad, ascii));
    }
    out
}

/// Hex dump con límite de líneas.
pub fn hexdump_limited(data: &[u8], base_address: u64, max_lines: usize) -> String {
    let chunk_size = max_lines * 16;
    let slice = &data[..chunk_size.min(data.len())];
    hexdump(slice, base_address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hexdump_format() {
        let data = b"Hello, bitwise!";
        let out = hexdump(data, 0x1000);
        assert!(out.contains("0000000000001000"));
        assert!(out.contains("48 65 6c 6c 6f"));
        assert!(out.contains("|Hello, bitwise!|"));
    }
}
