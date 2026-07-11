//! Canonical differential adapter. All consensus decoding, hashing, receipt
//! encoding and sparse-tree updates are production noos-lumen import paths.
use noos_codec::{NoosDecode, NoosEncode};
use noos_crypto::{DomainId, Keypair};
use noos_lumen::{
    domain_hash,
    objects::{txid, wtxid, ReceiptV1, ResourceVector, TransactionV1, TransactionWitnessesV1},
    smt::Smt,
};
use std::{
    fmt::Write as _,
    io::{self, BufRead},
};

const FAMILY: &str = "noosphere-rust-production";
fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len().saturating_mul(2));
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}
fn unhex(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    };
    s.as_bytes()
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .map_err(|_| ())
                .and_then(|p| u8::from_str_radix(p, 16).map_err(|_| ()))
        })
        .collect()
}
fn err(e: noos_codec::CodecError) -> String {
    e.class_name().to_ascii_uppercase()
}
fn identity() -> Result<(), ()> {
    let key =
        Keypair::from_seed(*blake3::hash(b"NOOS production Rust client identity v1").as_bytes());
    let chain = [0x4eu8; 32];
    let genesis = [0x47u8; 32];
    let version = 1u16.to_le_bytes();
    let public = key.public_key();
    let sig = key
        .sign_domain(
            DomainId::SigPeer,
            &[&chain, &genesis, &version, public.as_bytes()],
        )
        .map_err(|_| ())?;
    println!(
        "{FAMILY},1,{},{},{}",
        hex(public.as_bytes()),
        hex(sig.as_bytes()),
        hex(&chain)
    );
    Ok(())
}
fn process(line: &str) -> String {
    let f: Vec<&str> = line.trim().split(',').collect();
    if f.len() != 12 {
        return "0,REJECT,MALFORMED,,,,0,0,0,0,0,,".into();
    }
    let id = f[0].parse::<u64>().unwrap_or(0);
    let txb = match unhex(f[1]) {
        Ok(v) => v,
        Err(()) => return format!("{id},REJECT,MALFORMED,,,,0,0,0,0,0,,"),
    };
    let witb = match unhex(f[2]) {
        Ok(v) => v,
        Err(()) => return format!("{id},REJECT,MALFORMED,,,,0,0,0,0,0,,"),
    };
    let empty = hex(&Smt::new().root());
    let empty_roots = [empty.as_str(); 6].join(";");
    let tx = match TransactionV1::decode_canonical(&txb) {
        Ok(v) => v,
        Err(e) => {
            return format!(
                "{id},REJECT,{},{},,,{},{},{},0,0,,",
                err(e),
                empty_roots,
                f[3],
                f[4],
                f[7]
            )
        }
    };
    let witnesses = match TransactionWitnessesV1::decode_canonical(&witb) {
        Ok(v) => v,
        Err(e) => {
            return format!(
                "{id},REJECT,{},{},,,{},{},{},0,0,,",
                err(e),
                empty_roots,
                f[3],
                f[4],
                f[7]
            )
        }
    };
    let tid = txid(&tx);
    let wid = wtxid(&tx, &witnesses);
    let status = f[8].parse::<u16>().unwrap_or(0);
    let charge = f[9].parse::<u128>().unwrap_or(0);
    let receipt = ReceiptV1 {
        txid: tid,
        status,
        fee_charged: charge,
        resources_used: ResourceVector::default(),
    };
    let rec = receipt.encode_canonical();
    let mut receipts = Smt::new();
    receipts.insert(tid, rec.clone());
    let roots = [
        empty.clone(),
        empty.clone(),
        empty.clone(),
        empty.clone(),
        hex(&receipts.root()),
        empty,
    ];
    let mut ordered = Vec::with_capacity(rec.len().saturating_add(4));
    ordered.extend_from_slice(&1u32.to_le_bytes());
    ordered.extend_from_slice(&rec);
    let execution = domain_hash("NOOS/BODY/RECEIPT/V1", &[&ordered]);
    let bh = unhex(f[11]).unwrap_or_default();
    let inv: Vec<u8> = bh.iter().map(|x| !x).collect();
    let fork = format!("{}:{}:{}:{}", f[4], f[3], f[5], hex(&inv));
    let (class, code) = if status == 0 {
        ("ACCEPT", "OK")
    } else {
        ("FAILED", "EXECUTION_FAILURE")
    };
    format!(
        "{id},{class},{code},{},{},{fork},{},{},{},{},{},{},{}",
        roots.join(";"),
        hex(&execution),
        f[3],
        f[4],
        f[7],
        f[9],
        f[10],
        hex(&tid),
        hex(&wid)
    )
}
fn main() {
    if std::env::args().nth(1).as_deref() == Some("--identity") {
        if identity().is_err() {
            std::process::exit(2)
        };
        return;
    }
    for line in io::stdin().lock().lines() {
        match line {
            Ok(v) if !v.trim().is_empty() => println!("{}", process(&v)),
            Ok(_) => {}
            Err(_) => std::process::exit(2),
        }
    }
}
