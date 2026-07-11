//! Per-peer outbound scheduling: priority vs normal lanes (p2p-v1.md §6).
//!
//! Consensus-over-AI law: the priority lane (braid header/vote/body + sync)
//! ALWAYS drains fully before the normal lane (tx, blob, loom) sends. The
//! node drives one in-flight request per peer, so lane order is also the
//! observed wire order.

use crate::envelope::{Lane, Protocol};
use std::collections::VecDeque;
use tokio::sync::oneshot;

use crate::node::SendError;

/// One queued outbound request: raw envelope bytes plus the reply slot.
#[derive(Debug)]
pub struct OutboundItem {
    pub protocol: Protocol,
    pub payload: Vec<u8>,
    pub reply: oneshot::Sender<Result<Vec<u8>, SendError>>,
    /// Remaining delivery attempts across reconnects.
    pub attempts_left: u8,
}

/// Two-lane bounded outbox.
#[derive(Debug)]
pub struct Outbox {
    priority: VecDeque<OutboundItem>,
    normal: VecDeque<OutboundItem>,
    capacity_per_lane: usize,
}

impl Outbox {
    pub fn new(capacity_per_lane: usize) -> Self {
        Outbox {
            priority: VecDeque::new(),
            normal: VecDeque::new(),
            capacity_per_lane: capacity_per_lane.max(1),
        }
    }

    /// Enqueues into the protocol's lane. On a full lane the item is refused
    /// (the reply slot fires `QueueFull`) — sender-side backpressure, never
    /// unbounded memory.
    pub fn push(&mut self, item: OutboundItem) {
        let lane = match item.protocol.lane() {
            Lane::Priority => &mut self.priority,
            Lane::Normal => &mut self.normal,
        };
        if lane.len() >= self.capacity_per_lane {
            let _ = item.reply.send(Err(SendError::QueueFull));
            return;
        }
        lane.push_back(item);
    }

    /// Puts an item back at the FRONT of its lane (send interrupted by a
    /// connection loss; retried on the next ready session).
    pub fn push_front(&mut self, item: OutboundItem) {
        match item.protocol.lane() {
            Lane::Priority => self.priority.push_front(item),
            Lane::Normal => self.normal.push_front(item),
        }
    }

    /// Dequeues the next item: priority lane strictly first.
    pub fn pop(&mut self) -> Option<OutboundItem> {
        self.priority
            .pop_front()
            .or_else(|| self.normal.pop_front())
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.priority.is_empty() && self.normal.is_empty()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.priority.len().saturating_add(self.normal.len())
    }

    /// Fails every queued item (peer rejected: wrong chain identity).
    pub fn fail_all(&mut self, err: SendError) {
        for item in self.priority.drain(..).chain(self.normal.drain(..)) {
            let _ = item.reply.send(Err(err));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn item(
        protocol: Protocol,
        marker: u8,
    ) -> (OutboundItem, oneshot::Receiver<Result<Vec<u8>, SendError>>) {
        let (tx, rx) = oneshot::channel();
        (
            OutboundItem {
                protocol,
                payload: vec![marker],
                reply: tx,
                attempts_left: 2,
            },
            rx,
        )
    }

    #[test]
    fn priority_drains_before_normal_regardless_of_arrival_order() {
        let mut ob = Outbox::new(64);
        // Burst of AI/application traffic first...
        for i in 0..10u8 {
            let (it, _rx) = item(Protocol::LumenTx, i);
            ob.push(it);
        }
        // ...then one consensus vote.
        let (vote, _rx) = item(Protocol::BraidVote, 0xFF);
        ob.push(vote);

        let first = ob.pop().unwrap();
        assert_eq!(first.protocol, Protocol::BraidVote, "vote drains first");
        for _ in 0..10 {
            assert_eq!(ob.pop().unwrap().protocol, Protocol::LumenTx);
        }
        assert!(ob.pop().is_none());
    }

    #[test]
    fn full_lane_refuses_with_queue_full() {
        let mut ob = Outbox::new(1);
        let (a, _rx_a) = item(Protocol::LumenTx, 1);
        ob.push(a);
        let (b, mut rx_b) = item(Protocol::LumenTx, 2);
        ob.push(b);
        assert!(matches!(
            rx_b.try_recv().unwrap(),
            Err(SendError::QueueFull)
        ));
        // The other lane is unaffected.
        let (c, _rx_c) = item(Protocol::BraidVote, 3);
        ob.push(c);
        assert_eq!(ob.len(), 2);
    }

    #[test]
    fn push_front_preserves_head_position() {
        let mut ob = Outbox::new(8);
        let (a, _r1) = item(Protocol::BraidVote, 1);
        let (b, _r2) = item(Protocol::BraidVote, 2);
        ob.push(a);
        ob.push(b);
        let head = ob.pop().unwrap();
        assert_eq!(head.payload, vec![1]);
        ob.push_front(head);
        assert_eq!(
            ob.pop().unwrap().payload,
            vec![1],
            "requeued item stays head"
        );
    }

    #[test]
    fn fail_all_flushes_both_lanes() {
        let mut ob = Outbox::new(8);
        let (a, mut ra) = item(Protocol::BraidVote, 1);
        let (b, mut rb) = item(Protocol::LumenTx, 2);
        ob.push(a);
        ob.push(b);
        ob.fail_all(SendError::PeerRejected);
        assert!(ob.is_empty());
        assert!(matches!(
            ra.try_recv().unwrap(),
            Err(SendError::PeerRejected)
        ));
        assert!(matches!(
            rb.try_recv().unwrap(),
            Err(SendError::PeerRejected)
        ));
    }
}
