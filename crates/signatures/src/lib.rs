//! The hash-based signature schemes leanVM aggregates: leanXMSS, stateful, and
//! leanSPHINCS, stateless. Both sign with WOTS+C, so the recursion guest verifies
//! both with one walk; leanXMSS hashes with its own tweakable hash, and leanSPHINCS
//! with FIPS 205's.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod lean_sphincs;
pub mod lean_xmss;
