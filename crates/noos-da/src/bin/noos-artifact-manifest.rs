use std::fs::File;
use std::io::{BufReader, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use noos_crypto::Hash32;
use noos_da::{ArtifactEncoderV1, ArtifactError, ArtifactManifestV1, ArtifactShareSink};

struct CommitmentOnlySink {
    stripes: u32,
    completed: u32,
}

impl ArtifactShareSink for CommitmentOnlySink {
    fn begin_artifact(
        &mut self,
        _source_length: u64,
        _protocol_payload_root: &Hash32,
        _published_sha256: &[u8; 32],
        stripe_count: u32,
    ) -> Result<(), ArtifactError> {
        self.stripes = stripe_count;
        eprintln!("encoding {stripe_count} stripes without retaining share bytes");
        Ok(())
    }

    fn stage_share(
        &mut self,
        _stripe: u32,
        _position: u8,
        _bytes: &[u8],
    ) -> Result<(), ArtifactError> {
        Ok(())
    }

    fn checkpoint_stripe(&mut self, stripe: u32) -> Result<(), ArtifactError> {
        self.completed = stripe.saturating_add(1);
        if self.completed == self.stripes || self.completed % 32 == 0 {
            eprintln!("committed {}/{} stripes", self.completed, self.stripes);
        }
        Ok(())
    }

    fn publish_manifest(&mut self, _manifest: &ArtifactManifestV1) -> Result<(), ArtifactError> {
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn run() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1);
    let source_path = PathBuf::from(
        args.next()
            .ok_or("usage: noos-artifact-manifest <source> <manifest-output>")?,
    );
    let output_path = PathBuf::from(
        args.next()
            .ok_or("usage: noos-artifact-manifest <source> <manifest-output>")?,
    );
    if args.next().is_some() {
        return Err("usage: noos-artifact-manifest <source> <manifest-output>".into());
    }

    let source = File::open(&source_path).map_err(|error| format!("open source: {error}"))?;
    let mut source = BufReader::with_capacity(1024 * 1024, source);
    let encoder = ArtifactEncoderV1::new().map_err(|error| error.to_string())?;
    let mut sink = CommitmentOnlySink {
        stripes: 0,
        completed: 0,
    };
    let manifest = encoder
        .encode(&mut source, &mut sink, 1)
        .map_err(|error| error.to_string())?;
    let canonical = manifest.canonical_bytes();

    let parent = output_path
        .parent()
        .ok_or("manifest output must have a parent directory")?;
    std::fs::create_dir_all(parent).map_err(|error| format!("create output directory: {error}"))?;
    let partial = output_path.with_extension("partial");
    let mut output = File::create(&partial).map_err(|error| format!("create output: {error}"))?;
    output
        .write_all(&canonical)
        .and_then(|()| output.sync_all())
        .map_err(|error| format!("write output: {error}"))?;
    std::fs::rename(&partial, &output_path).map_err(|error| format!("publish output: {error}"))?;

    println!("source_bytes={}", manifest.source_length);
    println!("published_sha256={}", hex(&manifest.published_sha256));
    println!(
        "protocol_payload_root={}",
        hex(manifest.protocol_payload_root.as_bytes())
    );
    println!("manifest_root={}", hex(manifest.manifest_root().as_bytes()));
    println!("stripes={}", manifest.stripes.len());
    println!("manifest_bytes={}", canonical.len());
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}
