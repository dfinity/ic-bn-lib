use std::cell::RefCell;

use candid::Principal;
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager},
    DefaultMemoryImpl, StableBTreeMap, StableCell,
};

use crate::state::CanisterState;

// Maximum number of domains stored in the canister
pub const MAX_STORED_DOMAINS: u64 = 1_000_000;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    pub static AUTHORIZED_PRINCIPAL: RefCell<Option<Principal>> = RefCell::default();

    pub static STATE: RefCell<CanisterState> = RefCell::new(
        CanisterState {
            domains: StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0)))),
            last_change: StableCell::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))), 0),
            max_domains: MAX_STORED_DOMAINS,
        }
    );
}
