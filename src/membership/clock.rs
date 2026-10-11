//! One observation floor shared by membership and its original legal gate.
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

pub(super) struct ObservedClock<C> {
    source: C,
    sample: std::sync::Mutex<()>,
    floor: AtomicI64,
    poisoned: AtomicBool,
}
impl<C> ObservedClock<C> {
    pub(super) fn new(source: C) -> Self {
        Self {
            source,
            sample: std::sync::Mutex::new(()),
            floor: AtomicI64::new(i64::MIN),
            poisoned: AtomicBool::new(false),
        }
    }
}
impl<C> std::ops::Deref for ObservedClock<C> {
    type Target = C;
    fn deref(&self) -> &C {
        &self.source
    }
}
impl<C: clbs::Clock> clbs::Clock for ObservedClock<C> {
    fn now(&self) -> clbs::Result<i64> {
        if self.poisoned.load(Ordering::SeqCst) {
            return Err(clbs::Error::Clock);
        }
        // Serialize ONLY synchronous sampling, so scheduling between two
        // otherwise monotonic source reads cannot manufacture a rollback.
        let _sample = self.sample.lock().map_err(|_| clbs::Error::Clock)?;
        if self.poisoned.load(Ordering::SeqCst) {
            return Err(clbs::Error::Clock);
        }
        let now = self.source.now().map_err(|_| clbs::Error::Clock)?;
        if now < 0 || chrono::DateTime::from_timestamp(now, 0).is_none() {
            self.poisoned.store(true, Ordering::SeqCst);
            return Err(clbs::Error::Clock);
        }
        let previous = self.floor.fetch_max(now, Ordering::SeqCst);
        if now < previous {
            self.poisoned.store(true, Ordering::SeqCst);
        }
        if self.poisoned.load(Ordering::SeqCst) {
            Err(clbs::Error::Clock)
        } else {
            Ok(now)
        }
    }
}

#[cfg(test)]
mod tests;
