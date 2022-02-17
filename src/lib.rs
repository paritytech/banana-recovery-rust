//! Bananasplit
//!
//! Recovers secrets from split chunks according to the banana [split protocol](https://github.com/paritytech/banana_split).

#![deny(missing_docs)]
#![deny(unused_crate_dependencies)]
#![deny(unused_results)]
// #![deny(non_exhaustive_omitted_patterns)]

mod error;
mod shares;
mod tests;

pub use error::Error;
pub use shares::{NextAction, Share, ShareSet};
