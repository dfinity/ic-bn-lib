//! Candid types for the IC SMTP protocol.
//!
//! These live in [`ic_smtp_gateway_protocol`], alongside the normative
//! `.did` specification in
//! <https://github.com/dfinity/ic-smtp-gateway-protocol>, so that the gateway,
//! the canisters it delivers to and their tests all share one definition of the
//! wire format instead of each re-declaring it. The crate's own test module
//! pins the Candid traps (integer widths, case-sensitive variant labels, which
//! records are deliberately permissive) and is where those tests now live.
//!
//! This module is kept as a re-export rather than removed: downstream code -
//! `ic-gateway` in particular - imports these types as
//! `ic_bn_lib::smtp::ic::candid::*`.

pub use ic_smtp_gateway_protocol::*;
