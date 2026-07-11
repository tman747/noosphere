//! Deterministic, bounded decoder/VM/protocol mutation battery.
//! `NOOS_FUZZ_ITERS` is the exact iteration count; a fixed seed makes every
//! release run reproducible and a panic is always a test failure.
#![allow(clippy::arithmetic_side_effects)]

use noos_codec::NoosDecode;
use noos_grain::{decode_formula, decode_subject, eval, Meter, GRAIN_VERSION};
use noos_lumen::objects::{ActionV1, TransactionV1, TransactionWitnessesV1};

struct SplitMix64(u64);
impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn mutate(rng: &mut SplitMix64, buf: &mut Vec<u8>) {
    match rng.next() % 6 {
        0 if !buf.is_empty() => {
            let i = (rng.next() as usize) % buf.len();
            buf[i] ^= 1u8 << (rng.next() % 8);
        }
        1 if !buf.is_empty() => {
            let i = (rng.next() as usize) % buf.len();
            buf.remove(i);
        }
        2 if buf.len() < 4096 => {
            let i = (rng.next() as usize) % (buf.len() + 1);
            buf.insert(i, rng.next() as u8);
        }
        3 if buf.len() < 4096 => buf.extend_from_slice(&(rng.next() as u32).to_le_bytes()),
        4 => buf.truncate((rng.next() as usize) % (buf.len() + 1)),
        _ => {
            if buf.len() < 4096 {
                buf.push(0);
            }
        }
    }
}

#[test]
fn decoder_vm_protocol_battery() {
    let iters: u64 = match std::env::var("NOOS_FUZZ_ITERS") {
        Ok(value) => {
            let Ok(parsed) = value.parse() else {
                panic!("NOOS_FUZZ_ITERS must be u64");
            };
            parsed
        }
        Err(_) => 10_000,
    };
    let mut rng = SplitMix64(0x4E4F_4F53_4655_5A5A);
    let seeds: [&[u8]; 6] = [&[], &[0], &[1, 0], &[2, 0, 0], &[1, 1, 0], &[0xff; 16]];
    for i in 0..iters {
        let mut bytes = seeds[(rng.next() as usize) % seeds.len()].to_vec();
        for _ in 0..=rng.next() % 8 {
            mutate(&mut rng, &mut bytes);
        }
        let result = std::panic::catch_unwind(|| {
            let _ = TransactionV1::decode_canonical(&bytes);
            let _ = TransactionWitnessesV1::decode_canonical(&bytes);
            let _ = ActionV1::decode_canonical(&bytes);
            if let (Ok(subject), Ok(formula)) = (decode_subject(&bytes), decode_formula(&bytes)) {
                let mut meter = Meter::new(10_000, 16_384);
                let _ = eval(GRAIN_VERSION, subject, formula, &mut meter);
            }
        });
        assert!(
            result.is_ok(),
            "host panic at deterministic mutation {i}, bytes={bytes:02x?}"
        );
    }
    println!("RESULT decoder_vm_protocol_battery=PASS iterations={iters} seed=0x4e4f4f5346555a5a");
}
