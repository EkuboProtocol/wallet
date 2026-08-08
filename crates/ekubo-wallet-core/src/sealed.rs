//! Marker traits that close the kernel's two capability traits to outside
//! implementation.
//!
//! [`crate::custody::KeyStore`] and [`crate::human_presence::HumanPresence`]
//! are both `pub`, because presentation code has to name them to hand one to
//! an orchestrator entry point. Being `pub` also let anything outside this
//! crate *implement* them, and for these two that is not a hypothetical
//! untidiness:
//!
//! - A `HumanPresence` whose `confirm` returns `Ok(())` satisfies every owner
//!   authentication in the process without a person being present. Signing a
//!   reviewed message, exporting a private key, and removing a wallet are all
//!   gated on exactly that call, so one four-line impl in the presentation
//!   crate reopens every gate the kernel closed.
//! - A `KeyStore` chooses what `load` returns. Substituting a key is already
//!   refused downstream — `load_matching_signer` checks the derived address
//!   against the wallet metadata — but an outside implementation still decides
//!   whether `insert_new` really stored the key it was handed and whether
//!   `delete` really deleted one.
//!
//! Making these private supertraits is what forbids that. The module is
//! private to the kernel, so no other crate can name the marker, and no other
//! crate can therefore implement the traits that require it. The set of key
//! stores and presence backends is closed, and reading this crate enumerates
//! it.
//!
//! Adding a backend is still perfectly possible; it just has to happen in
//! here, which is where an auditor is already looking.

/// Implemented only by the key stores in [`crate::custody`].
pub trait SealedKeyStore {}

/// Implemented only by the presence backends in [`crate::human_presence`].
pub trait SealedHumanPresence {}
