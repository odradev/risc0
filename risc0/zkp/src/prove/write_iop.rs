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

use alloc::vec::Vec;
use core::marker::PhantomData;

use risc0_core::field::{Elem, Field};

use crate::core::{config::ConfigRng, sha::Digest};

pub struct WriteIOP<F: Field, R: ConfigRng<F>> {
    pub proof: Vec<u32>,
    pub rng: R,
    phantom: PhantomData<F>,
}

impl<F: Field, R: ConfigRng<F>> WriteIOP<F, R> {
    /// Create a new empty proof
    pub fn new() -> Self {
        Self {
            proof: Vec::new(),
            rng: R::new(),
            phantom: PhantomData,
        }
    }

    /// Called by the prover to write some data.
    ///
    /// This data is not cryptographically verifiable on its own,
    /// but is typically committed by a later hash which includes it.
    pub fn write_u32_slice(&mut self, slice: &[u32]) {
        self.proof.extend_from_slice(slice);
    }

    /// Write some field elements to this IOP.
    pub fn write_field_elem_slice<T: Elem>(&mut self, slice: &[T]) {
        self.proof.extend(Elem::as_u32_slice(slice))
    }

    /// Write some plain old data to this IOP.
    pub fn write_pod_slice<T: bytemuck::Pod>(&mut self, slice: &[T]) {
        self.proof.extend(bytemuck::cast_slice(slice))
    }

    /// Called by the prover to commit to some hash (usually data written
    /// earlier or a Merkle root).
    pub fn commit(&mut self, message: &Digest) {
        self.rng.mix(message);
    }

    /// Get a cryptographically uniform u32
    pub fn random_u32(&mut self) -> u32 {
        self.rng.random_u32()
    }

    /// Get a cryptographically uniform field element
    pub fn random_elem(&mut self) -> F::Elem {
        self.rng.random_elem()
    }

    /// Get a cryptographically uniform extension field element
    pub fn random_ext_elem(&mut self) -> F::ExtElem {
        self.rng.random_ext_elem()
    }
}
