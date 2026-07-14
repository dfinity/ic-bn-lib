use std::cell::RefCell;

use candid::Principal;
use ic_stable_structures::{
    DefaultMemoryImpl, StableBTreeMap, StableCell,
    memory_manager::{MemoryId, MemoryManager},
};

use crate::state::CanisterState;

/// Maximum number of domains stored in the canister
pub const MAX_STORED_DOMAINS: u64 = 1_000_000;

thread_local! {
    // `pub(crate)` so the certificate migration in `state.rs` can open a second, temporary
    // view over the domains memory region (MemoryId 0) using the pre-migration entry shape.
    pub(crate) static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    pub static AUTHORIZED_PRINCIPAL: RefCell<Option<Principal>> = RefCell::default();

    pub static STATE: RefCell<CanisterState> = RefCell::new(
        CanisterState {
            domains: StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0)))),
            last_change: StableCell::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))), 0),
            certificates: StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2)))),
            max_domains: MAX_STORED_DOMAINS,
            certificates_migrated: StableCell::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3))), false),
        }
    );
}
