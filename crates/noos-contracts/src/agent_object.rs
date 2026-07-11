//! One application-level agent object. Effects remain routed exclusively by
//! [`ActionRouter`]; reputation and commerce settlement carry no consensus
//! weight and cannot construct route tickets.

use crate::router::ActionRouter;
use noos_commerce::{Commerce, LineageReputation};

pub const ADDS_CONSENSUS_MECHANISM: bool = false;

#[derive(Default)]
pub struct AgentProtocolObject {
    router: ActionRouter,
    reputation: LineageReputation,
    commerce: Commerce,
}
impl AgentProtocolObject {
    #[must_use]
    pub fn new(router: ActionRouter, reputation: LineageReputation, commerce: Commerce) -> Self {
        Self {
            router,
            reputation,
            commerce,
        }
    }

    #[must_use]
    pub fn router(&self) -> &ActionRouter {
        &self.router
    }

    pub fn router_mut(&mut self) -> &mut ActionRouter {
        &mut self.router
    }

    #[must_use]
    pub fn reputation(&self) -> &LineageReputation {
        &self.reputation
    }

    pub fn reputation_mut(&mut self) -> &mut LineageReputation {
        &mut self.reputation
    }

    #[must_use]
    pub fn commerce(&self) -> &Commerce {
        &self.commerce
    }

    pub fn commerce_mut(&mut self) -> &mut Commerce {
        &mut self.commerce
    }
}
