// Copyright 2023 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(alloc_error_handler))]
#![deny(rustdoc::broken_intra_doc_links)]

extern crate alloc;

#[cfg(feature = "binfmt")]
pub mod binfmt;
mod control_id;
#[cfg(any(target_os = "zkvm", doc))]
pub mod guest;
#[cfg(feature = "prove")]
pub mod prove;
pub mod receipt;
pub mod serde;
pub mod sha;
#[cfg(test)]
mod tests;

pub use anyhow::Result;
use control_id::CONTROL_ID;
use control_id::POSEIDON_CONTROL_ID;
use crate::control_id::BLAKE2B_CONTROL_ID;
use hex::FromHex;
use risc0_zkp::core::blake2b::{ConfigHashBlake2b, Blake2bHasher};
use risc0_zkp::core::config::{ConfigHashPoseidon, ConfigHashSha256};
use risc0_zkp::core::digest::Digest;
use risc0_zkp::core::sha::Sha256;
pub use risc0_zkvm_platform::{memory::MEM_SIZE, PAGE_SIZE};

#[cfg(feature = "binfmt")]
pub use crate::binfmt::{elf::Program, image::MemoryImage};
#[cfg(feature = "prove")]
pub use crate::prove::{loader::Loader, Prover, ProverOpts};
pub use crate::receipt::Receipt;

const CIRCUIT: risc0_circuit_rv32im::CircuitImpl = risc0_circuit_rv32im::CircuitImpl::new();

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlId {
    pub table: alloc::vec::Vec<Digest>,
}

pub trait ControlIdLocator {
    fn get_control_id() -> ControlId;
}

impl<S: Sha256> ControlIdLocator for ConfigHashSha256<S> {
    fn get_control_id() -> ControlId {
        let mut table = alloc::vec::Vec::new();
        for entry in CONTROL_ID {
            table.push(Digest::from_hex(entry).unwrap());
        }
        ControlId { table }
    }
}

impl ControlIdLocator for ConfigHashPoseidon {
    fn get_control_id() -> ControlId {
        let mut table = alloc::vec::Vec::new();
        for entry in POSEIDON_CONTROL_ID {
            table.push(Digest::from_hex(entry).unwrap());
        }
        ControlId { table }
    }
}

impl<T: Blake2bHasher> ControlIdLocator for ConfigHashBlake2b<T> {
    fn get_control_id() -> ControlId {
        let mut table = alloc::vec::Vec::new();
        for entry in BLAKE2B_CONTROL_ID {
            table.push(Digest::from_hex(entry).unwrap());
        }
        ControlId { table }
    }
}