//! Artifact-only node store port.
//!
//! This channel, worker, and failure type are deliberately separate from the
//! consensus `StorePort`. Artifact backpressure or store failure therefore
//! cannot occupy the consensus-store queue or become a node startup/finality
//! prerequisite.

use std::fmt;
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};

use noos_da::ARTIFACT_SHARE_BYTES;
use noos_store::{ArtifactKey, ArtifactStore, ArtifactStoreError};

#[derive(Debug)]
pub enum ArtifactPortError {
    QueueFull,
    Offline,
    Store(ArtifactStoreError),
    InvalidReply,
}

impl fmt::Display for ArtifactPortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueueFull => f.write_str("artifact-store queue full"),
            Self::Offline => f.write_str("artifact store offline"),
            Self::Store(e) => write!(f, "artifact store: {e}"),
            Self::InvalidReply => f.write_str("artifact-store worker returned an invalid reply"),
        }
    }
}
impl std::error::Error for ArtifactPortError {}

pub trait ArtifactReadPort: Send + Sync {
    fn manifest(&self, artifact: ArtifactKey) -> Result<Vec<u8>, ArtifactPortError>;
    fn share(
        &self,
        artifact: ArtifactKey,
        stripe: u32,
        position: u8,
    ) -> Result<Vec<u8>, ArtifactPortError>;
}

#[derive(Clone)]
pub struct ArtifactStoreClient {
    tx: mpsc::SyncSender<ArtifactStoreMsg>,
}

pub struct ArtifactStoreWorker {
    join: Option<JoinHandle<()>>,
}

impl ArtifactStoreWorker {
    pub fn join(mut self) -> thread::Result<()> {
        self.join.take().expect("worker handle present").join()
    }
}

impl Drop for ArtifactStoreWorker {
    fn drop(&mut self) {
        // Dropping the client(s) closes the worker naturally. A detached
        // worker is preferable to blocking a node shutdown path here.
        let _ = self.join.take();
    }
}

enum ArtifactStoreMsg {
    Manifest {
        artifact: ArtifactKey,
        reply: mpsc::Sender<Result<Vec<u8>, ArtifactStoreError>>,
    },
    Share {
        artifact: ArtifactKey,
        stripe: u32,
        position: u8,
        reply: mpsc::Sender<Result<Vec<u8>, ArtifactStoreError>>,
    },
}

pub fn spawn_artifact_store_port(
    store: ArtifactStore,
    queue_capacity: usize,
) -> Result<(ArtifactStoreClient, ArtifactStoreWorker), ArtifactPortError> {
    if queue_capacity == 0 {
        return Err(ArtifactPortError::QueueFull);
    }
    let (tx, rx) = mpsc::sync_channel(queue_capacity);
    let store = Arc::new(Mutex::new(store));
    let join = thread::Builder::new()
        .name("noos-artifact-store".into())
        .spawn(move || {
            while let Ok(message) = rx.recv() {
                match message {
                    ArtifactStoreMsg::Manifest { artifact, reply } => {
                        let result = store
                            .lock()
                            .map_err(|_| offline_store_error())
                            .and_then(|s| s.read_manifest(&artifact));
                        let _ = reply.send(result);
                    }
                    ArtifactStoreMsg::Share {
                        artifact,
                        stripe,
                        position,
                        reply,
                    } => {
                        let result =
                            store
                                .lock()
                                .map_err(|_| offline_store_error())
                                .and_then(|s| {
                                    let mut bytes = vec![0_u8; ARTIFACT_SHARE_BYTES];
                                    s.read_share(&artifact, stripe, position, &mut bytes)?;
                                    Ok(bytes)
                                });
                        let _ = reply.send(result);
                    }
                }
            }
        })
        .map_err(|_| ArtifactPortError::Offline)?;
    Ok((
        ArtifactStoreClient { tx },
        ArtifactStoreWorker { join: Some(join) },
    ))
}

impl ArtifactReadPort for ArtifactStoreClient {
    fn manifest(&self, artifact: ArtifactKey) -> Result<Vec<u8>, ArtifactPortError> {
        let (reply, rx) = mpsc::channel();
        self.tx
            .try_send(ArtifactStoreMsg::Manifest { artifact, reply })
            .map_err(send_error)?;
        rx.recv()
            .map_err(|_| ArtifactPortError::Offline)?
            .map_err(ArtifactPortError::Store)
    }

    fn share(
        &self,
        artifact: ArtifactKey,
        stripe: u32,
        position: u8,
    ) -> Result<Vec<u8>, ArtifactPortError> {
        if position >= 12 {
            return Err(ArtifactPortError::InvalidReply);
        }
        let (reply, rx) = mpsc::channel();
        self.tx
            .try_send(ArtifactStoreMsg::Share {
                artifact,
                stripe,
                position,
                reply,
            })
            .map_err(send_error)?;
        let bytes = rx
            .recv()
            .map_err(|_| ArtifactPortError::Offline)?
            .map_err(ArtifactPortError::Store)?;
        if bytes.len() != ARTIFACT_SHARE_BYTES {
            return Err(ArtifactPortError::InvalidReply);
        }
        Ok(bytes)
    }
}

fn send_error<T>(error: mpsc::TrySendError<T>) -> ArtifactPortError {
    match error {
        mpsc::TrySendError::Full(_) => ArtifactPortError::QueueFull,
        mpsc::TrySendError::Disconnected(_) => ArtifactPortError::Offline,
    }
}

fn offline_store_error() -> ArtifactStoreError {
    ArtifactStoreError::InvalidConfig("artifact worker mutex poisoned")
}
