//! Raw differential adapter for M-CLOCK. Input is a concatenation of pairs
//! of 80-byte fork tuples; output is one winner byte per pair.
#![forbid(unsafe_code)]

use noos_braid::ForkScore;
use noos_ground::U256;
use std::io::{self, Read, Write};

const TUPLE_BYTES: usize = 80;
const PAIR_BYTES: usize = TUPLE_BYTES * 2;

fn parse(input: &[u8]) -> ForkScore {
    let finalized_epoch = u64::from_le_bytes(input[0..8].try_into().unwrap_or([0; 8]));
    let justified_epoch = u64::from_le_bytes(input[8..16].try_into().unwrap_or([0; 8]));
    let work = input[16..48].try_into().unwrap_or([0; 32]);
    let block_hash = input[48..80].try_into().unwrap_or([0; 32]);
    ForkScore {
        finalized_epoch,
        justified_epoch,
        work_since_finalized: U256::from_le_bytes(&work),
        block_hash,
    }
}

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % PAIR_BYTES != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "M-CLOCK corpus is not an exact tuple-pair sequence",
        ));
    }
    let mut output = Vec::with_capacity(input.len() / PAIR_BYTES);
    for pair in input.chunks_exact(PAIR_BYTES) {
        let left = parse(&pair[..TUPLE_BYTES]);
        let right = parse(&pair[TUPLE_BYTES..]);
        output.push(match left.cmp(&right) {
            std::cmp::Ordering::Greater => b'a',
            std::cmp::Ordering::Less => b'b',
            std::cmp::Ordering::Equal => b'=',
        });
    }
    io::stdout().write_all(&output)
}
