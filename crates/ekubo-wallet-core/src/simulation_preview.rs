//! Short-lived display evidence, never a simulation handle or signing input.
use crate::simulation::{BalanceChanges, SimulationResult};
use std::{
    collections::BTreeMap,
    sync::{LazyLock, Mutex},
    time::{Duration, Instant},
};
use uuid::Uuid;

type Key = (Uuid, u64, String);
#[derive(Default)]
struct Cache(BTreeMap<Key, (Instant, BalanceChanges)>);
static CACHE: LazyLock<Mutex<Cache>> = LazyLock::new(|| Mutex::new(Cache::default()));
const TTL: Duration = Duration::from_secs(120);
const CAPACITY: usize = 64;

impl Cache {
    fn record(&mut self, key: Key, result: &SimulationResult, now: Instant) {
        self.0
            .retain(|_, (at, _)| now.saturating_duration_since(*at) < TTL);
        // A failed real-chain refresh invalidates older evidence. Fork results
        // cannot replace evidence about the actual chain.
        if result.fork.is_some() {
            return;
        }
        self.0.remove(&key);
        let Some(changes) = result
            .balance_changes
            .as_ref()
            .filter(|changes| result.simulation.success && changes.tokens.len() <= 128)
        else {
            return;
        };
        if self.0.len() >= CAPACITY
            && let Some(oldest) = self
                .0
                .iter()
                .min_by_key(|(_, (at, _))| *at)
                .map(|(key, _)| key.clone())
        {
            self.0.remove(&oldest);
        }
        self.0.insert(key, (now, changes.clone()));
    }
    fn get(&mut self, key: &Key, now: Instant) -> Option<BalanceChanges> {
        self.0
            .retain(|_, (at, _)| now.saturating_duration_since(*at) < TTL);
        self.0.get(key).map(|(_, changes)| changes.clone())
    }
}

pub(crate) fn invalidate(wallet: Uuid, chain: u64, digest: &str) {
    CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .0
        .remove(&(wallet, chain, digest.to_owned()));
}

pub(crate) fn record(wallet: Uuid, chain: u64, result: &SimulationResult) {
    CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .record(
            (wallet, chain, result.digest.clone()),
            result,
            Instant::now(),
        );
}

/// Read recent, successful, real-chain balance evidence for this exact wallet
/// incarnation, chain and plan digest. No RPC, policy verdict or send handle.
#[must_use]
pub fn balance_changes(wallet: Uuid, chain: u64, digest: &str) -> Option<BalanceChanges> {
    CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&(wallet, chain, digest.to_owned()), Instant::now())
}

#[cfg(test)]
#[path = "simulation_preview_test.rs"]
mod tests;
