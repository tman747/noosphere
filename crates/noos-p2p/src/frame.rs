//! Bounded wire frames (p2p-v1.md §4).
//!
//! Every substream message is one frame: a `u32` little-endian payload length
//! followed by exactly `len` payload bytes. The length is validated against
//! the frame bound BEFORE any allocation or payload read; an oversize
//! declaration is a protocol violation (the caller disconnects the peer), not
//! a recoverable decode error.

use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Hard frame law (p2p-v1.md §4): 1 MiB of payload per frame.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Handshake frames are tiny; a large declaration there is equally violating.
pub const MAX_HANDSHAKE_FRAME_BYTES: usize = 4096;

/// Frame I/O outcome.
#[derive(Debug)]
pub enum FrameError {
    /// Declared length exceeds the frame bound: protocol violation.
    Oversize { declared: u64, max: usize },
    /// Peer closed the stream mid-frame or before a frame.
    Closed,
    /// Underlying transport error.
    Io(std::io::Error),
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FrameError::Oversize { declared, max } => {
                write!(f, "oversize frame: declared {declared} bytes, max {max}")
            }
            FrameError::Closed => f.write_str("stream closed"),
            FrameError::Io(e) => write!(f, "frame io: {e}"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<std::io::Error> for FrameError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            FrameError::Closed
        } else {
            FrameError::Io(e)
        }
    }
}

/// Reads one frame, bounding the declared length by `max` before allocating.
pub async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    max: usize,
) -> Result<Vec<u8>, FrameError> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > max {
        return Err(FrameError::Oversize {
            declared: len as u64,
            max,
        });
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}

/// Writes one frame. An oversized local payload is a caller bug surfaced as
/// an error (never sent): honest nodes must shape replies to fit (§4.2).
pub async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    payload: &[u8],
    max: usize,
) -> Result<(), FrameError> {
    if payload.len() > max {
        return Err(FrameError::Oversize {
            declared: payload.len() as u64,
            max,
        });
    }
    stream.write_all(&(payload.len() as u32).to_le_bytes()).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

/// Writes a deliberately mis-declared frame header (conformance testing only:
/// the loopback matrix uses this to prove the receiver's oversize law).
pub async fn write_raw_declared<S: AsyncWrite + Unpin>(
    stream: &mut S,
    declared_len: u32,
    payload: &[u8],
) -> Result<(), FrameError> {
    stream.write_all(&declared_len.to_le_bytes()).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use futures::io::Cursor;

    #[test]
    fn round_trip() {
        block_on(async {
            let mut buf = Cursor::new(Vec::new());
            write_frame(&mut buf, b"hello", MAX_FRAME_BYTES).await.unwrap();
            let mut rd = Cursor::new(buf.into_inner());
            let got = read_frame(&mut rd, MAX_FRAME_BYTES).await.unwrap();
            assert_eq!(got, b"hello");
        });
    }

    #[test]
    fn oversize_declaration_rejects_before_payload_read() {
        block_on(async {
            // Header only — no payload bytes exist; the bound check must fire
            // on the declaration, not on a failed read.
            let mut rd = Cursor::new(((MAX_FRAME_BYTES as u32) + 1).to_le_bytes().to_vec());
            match read_frame(&mut rd, MAX_FRAME_BYTES).await {
                Err(FrameError::Oversize { declared, max }) => {
                    assert_eq!(declared, MAX_FRAME_BYTES as u64 + 1);
                    assert_eq!(max, MAX_FRAME_BYTES);
                }
                other => panic!("expected oversize, got {other:?}"),
            }
        });
    }

    #[test]
    fn boundary_frame_passes() {
        block_on(async {
            let payload = vec![7u8; MAX_FRAME_BYTES];
            let mut buf = Cursor::new(Vec::new());
            write_frame(&mut buf, &payload, MAX_FRAME_BYTES).await.unwrap();
            let mut rd = Cursor::new(buf.into_inner());
            assert_eq!(read_frame(&mut rd, MAX_FRAME_BYTES).await.unwrap(), payload);
        });
    }

    #[test]
    fn truncated_payload_is_closed() {
        block_on(async {
            let mut bytes = 10u32.to_le_bytes().to_vec();
            bytes.extend_from_slice(b"abc"); // 3 of 10 declared bytes
            let mut rd = Cursor::new(bytes);
            assert!(matches!(
                read_frame(&mut rd, MAX_FRAME_BYTES).await,
                Err(FrameError::Closed)
            ));
        });
    }

    #[test]
    fn local_oversize_write_refused() {
        block_on(async {
            let payload = vec![0u8; MAX_FRAME_BYTES + 1];
            let mut buf = Cursor::new(Vec::new());
            assert!(matches!(
                write_frame(&mut buf, &payload, MAX_FRAME_BYTES).await,
                Err(FrameError::Oversize { .. })
            ));
            assert!(buf.into_inner().is_empty(), "nothing may be sent");
        });
    }
}
