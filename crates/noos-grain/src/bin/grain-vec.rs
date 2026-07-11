//! `grain-vec` — Rust-side CLI shim for the Grain differential gate
//! (`tools/gates/differential_grain.py`, plan §5.4).
//!
//! This binary is pure I/O plumbing over the `noos-grain` public API; it
//! contains no interpreter semantics and adds no dependencies.
//!
//! Line protocol (one request per line on stdin, one reply per line on
//! stdout; empty byte strings are spelled `-`):
//!
//! ```text
//! E <version> <meter_limit> <arena_limit> <subject_hex> <formula_hex>
//!   -> V <noun_hex> <charge>     (value outcome)
//!   -> T <trap_code> <charge>    (trap outcome; decode traps charge 0)
//! D <role: formula|subject> <hex>
//!   -> N <reencoded_hex>
//!   -> T <trap_code>
//! ```
//!
//! The `E` runner order matches spec §14: version gate before decoding,
//! then decode subject, decode formula, eval.

use std::io::{self, BufRead, BufWriter, Write};
use std::process::ExitCode;

use noos_grain::{decode_formula, decode_subject, encode_noun, eval, Meter, Noun, GRAIN_VERSION};

fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    if s == "-" {
        return Ok(Vec::new());
    }
    if !s.len().is_multiple_of(2) {
        return Err(format!("odd hex length {}", s.len()));
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len().wrapping_div(2));
    for pair in bytes.chunks_exact(2) {
        let hi = hex_nibble(pair[0]).ok_or_else(|| format!("bad hex byte {}", pair[0]))?;
        let lo = hex_nibble(pair[1]).ok_or_else(|| format!("bad hex byte {}", pair[1]))?;
        out.push(hi.wrapping_shl(4) | lo);
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(c.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

fn hex_out(b: &[u8]) -> String {
    if b.is_empty() {
        return "-".to_owned();
    }
    let mut s = Vec::with_capacity(b.len().wrapping_mul(2));
    for byte in b {
        s.push(HEX_DIGITS[usize::from(byte.wrapping_shr(4))]);
        s.push(HEX_DIGITS[usize::from(byte & 0xf)]);
    }
    String::from_utf8(s).unwrap_or_default()
}

fn handle(out: &mut impl Write, line: &str) -> Result<(), String> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let io_err = |e: io::Error| e.to_string();
    match fields[0] {
        "E" => {
            if fields.len() != 6 {
                return Err(format!("E wants 5 args, got {}", fields.len().saturating_sub(1)));
            }
            let version: u32 = fields[1].parse().map_err(|_| "bad version")?;
            let meter_limit: u64 = fields[2].parse().map_err(|_| "bad meter_limit")?;
            let arena_limit: u64 = fields[3].parse().map_err(|_| "bad arena_limit")?;
            let subj_hex = parse_hex(fields[4])?;
            let form_hex = parse_hex(fields[5])?;
            let mut meter = Meter::new(meter_limit, arena_limit);
            if version != GRAIN_VERSION {
                // Version gate fires before decoding (spec §14); operands
                // are irrelevant, so probe with the atom 0.
                let zero = Noun::atom_u64(0);
                match eval(version, zero.clone(), zero, &mut meter) {
                    Ok(_) => return Err("version gate did not trap".to_owned()),
                    Err(t) => {
                        writeln!(out, "T {} {}", t.code(), meter.spent()).map_err(io_err)?;
                        return Ok(());
                    }
                }
            }
            let subject = match decode_subject(&subj_hex) {
                Ok(n) => n,
                Err(t) => {
                    writeln!(out, "T {} 0", t.code()).map_err(io_err)?;
                    return Ok(());
                }
            };
            let formula = match decode_formula(&form_hex) {
                Ok(n) => n,
                Err(t) => {
                    writeln!(out, "T {} 0", t.code()).map_err(io_err)?;
                    return Ok(());
                }
            };
            match eval(version, subject, formula, &mut meter) {
                Ok(n) => writeln!(out, "V {} {}", hex_out(&encode_noun(&n)), meter.spent())
                    .map_err(io_err)?,
                Err(t) => {
                    writeln!(out, "T {} {}", t.code(), meter.spent()).map_err(io_err)?;
                }
            }
            Ok(())
        }
        "D" => {
            if fields.len() != 3 {
                return Err(format!("D wants 2 args, got {}", fields.len().saturating_sub(1)));
            }
            let b = parse_hex(fields[2])?;
            let decoded = match fields[1] {
                "formula" => decode_formula(&b),
                "subject" => decode_subject(&b),
                role => return Err(format!("unknown role {role:?}")),
            };
            match decoded {
                Ok(n) => writeln!(out, "N {}", hex_out(&encode_noun(&n))).map_err(io_err)?,
                Err(t) => writeln!(out, "T {}", t.code()).map_err(io_err)?,
            }
            Ok(())
        }
        cmd => Err(format!("unknown command {cmd:?}")),
    }
}

fn main() -> ExitCode {
    let stdin = io::stdin();
    let mut out = BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("grain-vec: {e}");
                return ExitCode::from(2);
            }
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Err(e) = handle(&mut out, line) {
            eprintln!("grain-vec: {e}");
            let _ = out.flush();
            return ExitCode::from(2);
        }
    }
    if out.flush().is_err() {
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}
