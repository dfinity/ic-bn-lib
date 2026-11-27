use std::cell::RefCell;

use candid::Principal;
use ic_stable_structures::{
    DefaultMemoryImpl, StableBTreeMap, StableCell,
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
};

use crate::state::CanisterState;

/// Maximum number of domains stored in the canister
pub const MAX_STORED_DOMAINS: u64 = 1_000_000;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    /// The only principal allowed to call the guarded methods. Kept in stable memory so that it
    /// survives upgrades. `None` means that no caller is authorized.
    ///
    /// MemoryId 3 must not be reused: an earlier version kept a `StableCell<bool>` there
    /// (`certificates_migrated`), which would decode as `Some(aaaaa-aa)`.
    pub static AUTHORIZED_PRINCIPAL: RefCell<StableCell<Option<Principal>, VirtualMemory<DefaultMemoryImpl>>> = RefCell::new(
        StableCell::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(4))), None)
    );

    pub static STATE: RefCell<CanisterState> = RefCell::new(
        CanisterState {
            domains: StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0)))),
            last_change: StableCell::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))), 0),
            certificates: StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2)))),
            max_domains: MAX_STORED_DOMAINS,
        }
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorized_principal_ignores_legacy_memory() {
        // State left by the certificates migration of an earlier version
        let mut migrated = StableCell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3))),
            false,
        );
        migrated.set(true);

        assert_eq!(AUTHORIZED_PRINCIPAL.with(|p| *p.borrow().get()), None);
    }
}
