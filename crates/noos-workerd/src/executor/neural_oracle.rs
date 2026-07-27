//! Worker-side construction of canonical neural-oracle commit/reveal actions.

use noos_codec::NoosEncode;
use noos_lumen::neural_oracle::{
    neural_output_root, neural_reply_commitment, neural_transcript_root, NeuralOracleCommitV1,
    NeuralOracleRevealV1, MAX_NEURAL_ORACLE_RESPONSE_BYTES,
};
use noos_lumen::objects::{ActionV1, BoundedBytes};
use noos_lumen::Hash32;
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeuralOracleArtifactError {
    InvalidQuery,
    InvalidResponseLimit,
    EmptyResponse,
    OversizedResponse,
}

/// Validated on-chain identity and private opening material for one WWM job.
pub struct NeuralOracleJob {
    query_id: Hash32,
    reporter_profile_id: Hash32,
    nonce: Hash32,
    max_response_bytes: usize,
}

impl Drop for NeuralOracleJob {
    fn drop(&mut self) {
        self.nonce.zeroize();
    }
}

pub struct NeuralOracleArtifacts {
    pub output_root: Hash32,
    pub transcript_root: Hash32,
    pub commit_action: Vec<u8>,
    pub reveal_action: Vec<u8>,
}

impl NeuralOracleJob {
    pub fn new(
        job_id: Hash32,
        query_id: Hash32,
        reporter_profile_id: Hash32,
        nonce: Hash32,
        max_response_bytes: u32,
    ) -> Result<Self, NeuralOracleArtifactError> {
        if query_id != job_id || reporter_profile_id == [0; 32] || nonce == [0; 32] {
            return Err(NeuralOracleArtifactError::InvalidQuery);
        }
        if max_response_bytes == 0 || max_response_bytes > MAX_NEURAL_ORACLE_RESPONSE_BYTES {
            return Err(NeuralOracleArtifactError::InvalidResponseLimit);
        }
        Ok(Self {
            query_id,
            reporter_profile_id,
            nonce,
            max_response_bytes: max_response_bytes as usize,
        })
    }

    #[must_use]
    pub fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    pub fn actions(
        &self,
        response: &[u8],
    ) -> Result<NeuralOracleArtifacts, NeuralOracleArtifactError> {
        if response.is_empty() {
            return Err(NeuralOracleArtifactError::EmptyResponse);
        }
        if response.len() > self.max_response_bytes {
            return Err(NeuralOracleArtifactError::OversizedResponse);
        }
        let output_root = neural_output_root(response);
        let transcript_root = neural_transcript_root(response);
        let commitment = neural_reply_commitment(
            &self.query_id,
            &self.reporter_profile_id,
            &output_root,
            &transcript_root,
            &self.nonce,
        );
        let commit = ActionV1::CommitNeuralOracleReply(NeuralOracleCommitV1 {
            query_id: self.query_id,
            reporter_profile_id: self.reporter_profile_id,
            commitment,
        });
        let reveal = ActionV1::RevealNeuralOracleReply(NeuralOracleRevealV1 {
            query_id: self.query_id,
            reporter_profile_id: self.reporter_profile_id,
            response: BoundedBytes::new(response.to_vec())
                .ok_or(NeuralOracleArtifactError::OversizedResponse)?,
            transcript_root,
            nonce: self.nonce,
        });
        Ok(NeuralOracleArtifacts {
            output_root,
            transcript_root,
            commit_action: commit.encode_canonical(),
            reveal_action: reveal.encode_canonical(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noos_codec::NoosDecode;

    #[test]
    fn artifacts_round_trip_as_exact_commit_and_reveal_actions() {
        let query_id = [7; 32];
        let reporter_profile_id = [8; 32];
        let nonce = [9; 32];
        let response = b"unmodified model response";
        let job = NeuralOracleJob::new(
            query_id,
            query_id,
            reporter_profile_id,
            nonce,
            response.len() as u32,
        )
        .unwrap();

        let artifacts = job.actions(response).unwrap();
        let commit = ActionV1::decode_canonical(&artifacts.commit_action).unwrap();
        let reveal = ActionV1::decode_canonical(&artifacts.reveal_action).unwrap();
        let ActionV1::CommitNeuralOracleReply(commit) = commit else {
            panic!("wrong commit action variant");
        };
        let ActionV1::RevealNeuralOracleReply(reveal) = reveal else {
            panic!("wrong reveal action variant");
        };

        assert_eq!(commit.query_id, query_id);
        assert_eq!(commit.reporter_profile_id, reporter_profile_id);
        assert_eq!(
            commit.commitment,
            neural_reply_commitment(
                &query_id,
                &reporter_profile_id,
                &artifacts.output_root,
                &artifacts.transcript_root,
                &nonce,
            )
        );
        assert_eq!(reveal.response.as_slice(), response);
        assert_eq!(reveal.transcript_root, artifacts.transcript_root);
        assert_eq!(reveal.nonce, nonce);
    }
}
