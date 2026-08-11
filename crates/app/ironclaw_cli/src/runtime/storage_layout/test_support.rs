//! Fault injection support for adoption-recovery tests.

use super::*;

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TestAdoptionFaultPoint {
    StagingChildrenCreated,
    FirstStateCopy,
    StateRename,
    MarkerRemovedBeforeStagingDirectoryRemoval,
}

#[cfg(test)]
thread_local! {
    static TEST_ADOPTION_FAULT: std::cell::Cell<Option<TestAdoptionFaultPoint>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(super) struct TestAdoptionFaultGuard;

#[cfg(test)]
impl TestAdoptionFaultGuard {
    pub(super) fn arm(point: TestAdoptionFaultPoint) -> Self {
        TEST_ADOPTION_FAULT.with(|fault| fault.set(Some(point)));
        Self
    }
}

#[cfg(test)]
impl Drop for TestAdoptionFaultGuard {
    fn drop(&mut self) {
        TEST_ADOPTION_FAULT.with(|fault| fault.set(None));
    }
}

#[cfg(test)]
pub(super) fn fail_at_test_adoption_fault(point: TestAdoptionFaultPoint) -> anyhow::Result<()> {
    let should_fail = TEST_ADOPTION_FAULT.with(|fault| {
        if fault.get() == Some(point) {
            fault.set(None);
            true
        } else {
            false
        }
    });
    if should_fail {
        bail!("injected ENOSPC-style adoption fault at {point:?}");
    }
    Ok(())
}
