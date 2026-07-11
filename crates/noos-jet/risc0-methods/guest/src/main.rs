#![no_main]

use noos_jet_risc0_shared::ProofInput;
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    let mut byte_len = [0u32; 1];
    env::read_slice(&mut byte_len);
    let len = usize::try_from(byte_len[0]).expect("guest input length fits usize");
    let mut bytes = vec![0u8; len];
    env::read_slice(&mut bytes);
    let input = ProofInput::decode(&bytes).expect("canonical proof input");
    let claim = input.execute().expect("valid certified RV32 execution");
    env::commit_slice(&claim.canonical_bytes());
}
