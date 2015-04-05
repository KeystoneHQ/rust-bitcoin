// Rust Bitcoin Library
// Written in 2014 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Rust Bitcoin Library
//!
//! This is a library for which supports the Bitcoin network protocol and associated
//! primitives. It is designed for Rust programs built to work with the Bitcoin
//! network.
//!
//! It is also written entirely in Rust to illustrate the benefits of strong type
//! safety, including ownership and lifetime, for financial and/or cryptographic
//! software.
//!

#![crate_name = "bitcoin"]
#![crate_type = "dylib"]
#![crate_type = "rlib"]

// Experimental features we need
#![feature(custom_derive, plugin)]
#![feature(overloaded_calls)]
#![feature(unsafe_destructor)]
#![feature(unboxed_closure_sugar)]
#![feature(unboxed_closures)]
#![feature(concat_idents)]
#![feature(slice_patterns)]

// Coding conventions
#![warn(non_uppercase_statics)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_doc)]

extern crate alloc;
extern crate byteorder;
extern crate collections;
extern crate num_cpus;
extern crate rand;
extern crate rustc_serialize as serialize;
extern crate serde;
#[plugin(serde_macros)]
extern crate test;
extern crate time;

extern crate secp256k1;
extern crate crypto;

#[macro_use]
mod internal_macros;
#[macro_use]
pub mod macros;
pub mod network;
pub mod blockdata;
pub mod util;
pub mod wallet;

/// I dunno where else to put this..
fn assert_type_is_copy<T: Copy>() { }

