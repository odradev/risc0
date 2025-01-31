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

use core::marker::PhantomData;

use risc0_core::field::{Elem, Field};

use crate::core::{config::ConfigRng, sha::Digest};

#[derive(Debug)]
pub struct ReadIOP<'a, F: Field, R: ConfigRng<F>> {
    proof: &'a [u32],
    rng: R,
    phantom: PhantomData<F>,
}

impl<'a, F: Field, R: ConfigRng<F>> ReadIOP<'a, F, R> {
    pub fn new(proof: &'a [u32]) -> Self {
        ReadIOP {
            proof,
            rng: R::new(),
            phantom: PhantomData,
        }
    }

    pub fn read_u32s(&mut self, n: usize) -> &'a [u32] {
        let u32s;
        (u32s, self.proof) = self.proof.split_at(n);
        u32s
    }

    /// Read some field elements from this IOP, and check to make sure
    /// they're not INVALID.
    pub fn read_field_elem_slice<T: Elem>(&mut self, n: usize) -> &'a [T] {
        let u32s = self.read_u32s(n * T::WORDS);
        T::from_u32_slice(u32s)
    }

    /// Read some plain old data from this IOP without doing any
    /// validation.  Prefer to use read_field_elem_slice if reading
    /// field elements.
    pub fn read_pod_slice<T: bytemuck::Pod>(&mut self, n: usize) -> &'a [T] {
        let u32s;
        (u32s, self.proof) = self
            .proof
            .split_at(n * core::mem::size_of::<T>() / core::mem::size_of::<u32>());
        bytemuck::cast_slice(u32s)
    }

    pub fn commit(&mut self, digest: &Digest) {
        self.rng.mix(digest);
    }

    /// Checks that the entire data of the IOP has been read.
    pub fn verify_complete(&self) {
        assert_eq!(self.proof.len(), 0);
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
